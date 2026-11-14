//! Local port forwarding through a chain of tunnel/proxy layers.
//!
//! The driver dials the database through a tunnel by starting a listener on `127.0.0.1:<port>` and
//! pointing the connection at it. Each accepted connection is forwarded through the configured
//! chain: the client connects to the first layer, which forwards to the second, and so on, with the
//! last layer forwarding to the real database server.
//!
//! The SSH layer is a real SSH client (password or private-key authentication) using
//! `direct-tcpip`; the proxy/HTTP layers speak an HTTP `CONNECT` handshake.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rustgrid_core::{TunnelAuth, TunnelKind, TunnelLayer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

/// Bound DNS, connection, authentication and forwarding setup, including stalled proxy replies.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// A boxed, bidirectional byte stream (a TCP socket, an SSH channel, or a proxied socket).
trait ByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ByteStream for T {}
type Stream = Box<dyn ByteStream>;

/// Load and unlock a key once, outside the async executor, rather than repeating bcrypt for every
/// socket in a database connection pool. Never derive Debug for credentials or decrypted keys.
struct PreparedLayer {
    layer: TunnelLayer,
    key: Option<Arc<russh::keys::PrivateKey>>,
    known_hosts: Option<PathBuf>,
}

/// A running tunnel: a local listener plus the task that accepts and forwards connections. Dropping
/// it stops the listener, so it must be kept alive for as long as the database connection is.
pub struct Tunnel {
    local_port: u16,
    task: JoinHandle<()>,
}

impl Tunnel {
    /// Start forwarding `127.0.0.1:<ephemeral>` to `target` through `layers` (outermost first).
    pub async fn start(
        layers: Vec<TunnelLayer>,
        target_host: String,
        target_port: u16,
    ) -> Result<Self, String> {
        Self::start_with_known_hosts(layers, target_host, target_port, None).await
    }

    // An explicit file is used by local tests; public callers always use ~/.ssh/known_hosts.
    async fn start_with_known_hosts(
        layers: Vec<TunnelLayer>,
        target_host: String,
        target_port: u16,
        known_hosts: Option<PathBuf>,
    ) -> Result<Self, String> {
        if layers.is_empty() {
            return Err("the tunnel chain is empty".to_string());
        }
        let mut layers = tokio::task::spawn_blocking(move || prepare_layers(layers))
            .await
            .map_err(|error| format!("could not prepare the tunnel credentials: {error}"))??;
        for prepared in &mut layers {
            prepared.known_hosts = known_hosts.clone();
        }
        let layers = Arc::new(layers);
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|error| format!("could not start the tunnel listener: {error}"))?;
        let local_port = listener
            .local_addr()
            .map_err(|error| format!("could not read the tunnel port: {error}"))?
            .port();

        // Establish a real connection before returning the local endpoint. Otherwise a rejected
        // SSH login or an unreadable key only closes the driver's socket and becomes a misleading
        // MongoDB timeout. This stream is reused for the first client, not a throwaway probe.
        let mut first_remote = Some(
            open_stream_with_timeout(&layers, (&target_host, target_port), CONNECT_TIMEOUT).await?,
        );

        let task = tokio::spawn(async move {
            // Owning the children here also closes existing forwards when the tunnel is dropped.
            let mut connections = JoinSet::new();
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted,
                    _ = connections.join_next(), if !connections.is_empty() => continue,
                };
                let (mut client, _peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::warn!(%error, "tunnel listener failed");
                        break;
                    }
                };
                let layers = Arc::clone(&layers);
                let target_host = target_host.clone();
                let prepared_remote = first_remote.take();
                connections.spawn(async move {
                    let remote = match prepared_remote {
                        Some(remote) => Ok(remote),
                        None => {
                            open_stream_with_timeout(
                                &layers,
                                (&target_host, target_port),
                                CONNECT_TIMEOUT,
                            )
                            .await
                        }
                    };
                    match remote {
                        Ok(mut remote) => {
                            if let Err(error) =
                                tokio::io::copy_bidirectional(&mut client, &mut remote).await
                            {
                                tracing::warn!(%error, "tunnel forwarding failed");
                            }
                        }
                        Err(error) => {
                            tracing::warn!(%error, "could not open a tunnel connection");
                        }
                    }
                });
            }
        });

        Ok(Self { local_port, task })
    }

    /// The local port the connection should point at.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn prepare_layers(layers: Vec<TunnelLayer>) -> Result<Vec<PreparedLayer>, String> {
    layers
        .into_iter()
        .map(|mut layer| {
            let key = if layer.kind == TunnelKind::Ssh && layer.auth == TunnelAuth::KeyFile {
                let key = load_ssh_key(&layer)?;
                // The decrypted key is sufficient for later connections; do not clone its
                // passphrase into every worker together with the tunnel settings.
                layer.password.clear();
                Some(Arc::new(key))
            } else {
                None
            };
            Ok(PreparedLayer {
                layer,
                key,
                known_hosts: None,
            })
        })
        .collect()
}

fn load_ssh_key(layer: &TunnelLayer) -> Result<russh::keys::PrivateKey, String> {
    let passphrase = (!layer.password.is_empty()).then_some(layer.password.as_str());
    russh::keys::load_secret_key(layer.key_path.trim(), passphrase).map_err(|error| match error {
        russh::keys::Error::KeyIsEncrypted => format!(
            "SSH key {} is encrypted; enter its key passphrase in Tunnel/Proxy.",
            layer.key_path
        ),
        russh::keys::Error::IO(_) => {
            format!("could not read the SSH key {}: {error}", layer.key_path)
        }
        _ if passphrase.is_some() => format!(
            "could not unlock the SSH key {}; check its passphrase and key file: {error}",
            layer.key_path
        ),
        _ => format!(
            "could not load the SSH key {}; if it is encrypted, enter its key passphrase in Tunnel/Proxy: {error}",
            layer.key_path
        ),
    })
}

async fn open_stream_with_timeout(
    layers: &[PreparedLayer],
    target: (&str, u16),
    timeout: Duration,
) -> Result<Stream, String> {
    tokio::time::timeout(timeout, open_stream(layers, target))
        .await
        .map_err(|_| {
            format!(
                "tunnel connection to {}:{} timed out after {} seconds; check the SSH/proxy server and forwarding destination",
                target.0,
                target.1,
                timeout.as_secs()
            )
        })?
}

/// Dial the first layer, then hand the socket off through every layer until it reaches `target`.
async fn open_stream(layers: &[PreparedLayer], target: (&str, u16)) -> Result<Stream, String> {
    let first = &layers
        .first()
        .ok_or_else(|| "the tunnel chain is empty".to_string())?
        .layer;
    let tcp = TcpStream::connect((first.host.as_str(), first.port))
        .await
        .map_err(|error| {
            format!(
                "could not reach the tunnel server {}:{}: {error}",
                first.host, first.port
            )
        })?;
    let _ = tcp.set_nodelay(true);

    let mut stream: Stream = Box::new(tcp);
    for (index, prepared) in layers.iter().enumerate() {
        let layer = &prepared.layer;
        let next = layers
            .get(index + 1)
            .map(|next| (next.layer.host.as_str(), next.layer.port))
            .unwrap_or(target);
        stream = match layer.kind {
            TunnelKind::Ssh => ssh_handshake(stream, prepared, next).await?,
            TunnelKind::Socks5 => socks5_connect(stream, layer, next).await?,
            TunnelKind::Http => http_connect(stream, layer, next).await?,
        };
    }
    Ok(stream)
}

/// Verify each SSH hop against the user's known_hosts before sending authentication information.
/// Unknown or changed keys are never trusted automatically.
struct Client {
    host: String,
    port: u16,
    known_hosts: Option<PathBuf>,
}

impl russh::client::Handler for Client {
    type Error = Box<dyn std::error::Error + Send + Sync>;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        use russh::keys::ssh_key::known_hosts::{KnownHosts, Marker};

        let key = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key,
            russh::keys::PublicKeyOrCertificate::Certificate(_) => {
                return Err("SSH host certificates are not supported; use a host public key recorded in ~/.ssh/known_hosts.".into());
            }
        };
        let path = self
            .known_hosts
            .clone()
            .or_else(|| std::env::home_dir().map(|home| home.join(".ssh").join("known_hosts")))
            .ok_or("could not locate ~/.ssh/known_hosts")?;
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => {
                return Err(format!("could not read {}: {error}", path.display()).into());
            }
        };
        // russh's matcher ignores marker lines. Honor revoked keys first, using ssh-key's parser.
        // Conservatively reject the same revoked key regardless of its recorded host patterns.
        for entry in KnownHosts::new(&contents) {
            let entry =
                entry.map_err(|error| format!("could not parse {}: {error}", path.display()))?;
            if entry.marker() == Some(&Marker::Revoked)
                && entry.public_key().key_data() == key.key_data()
            {
                return Err(format!(
                    "SSH host key for {}:{} is revoked in known_hosts. Connection refused.",
                    self.host, self.port
                )
                .into());
            }
        }
        let result = russh::keys::check_known_hosts_path(&self.host, self.port, key, &path);
        match result {
            Ok(true) => Ok(true),
            Ok(false) => Err(format!(
                "SSH host key for {}:{} is unknown ({}). Verify its fingerprint with your server administrator, then connect once using system ssh to record it in ~/.ssh/known_hosts.",
                self.host,
                self.port,
                key.fingerprint(russh::keys::HashAlg::Sha256)
            )
            .into()),
            Err(russh::keys::Error::KeyChanged { line }) => Err(format!(
                "SSH host key for {}:{} has changed (known_hosts line {line}). Connection refused; verify the server fingerprint with your administrator before updating ~/.ssh/known_hosts.",
                self.host, self.port
            )
            .into()),
            Err(error) => Err(format!(
                "could not verify the SSH host key for {}:{} against known_hosts: {error}",
                self.host, self.port
            )
            .into()),
        }
    }
}

/// A stream produced by an SSH `direct-tcpip` channel. It keeps the session handle alive alongside
/// the channel stream, because dropping the handle would tear the session (and the channel) down.
struct SshStream {
    stream: russh::ChannelStream<russh::client::Msg>,
    _session: russh::client::Handle<Client>,
}

impl AsyncRead for SshStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Authenticate an SSH session over `stream` and open a `direct-tcpip` channel to `target`.
async fn ssh_handshake(
    stream: Stream,
    prepared: &PreparedLayer,
    target: (&str, u16),
) -> Result<Stream, String> {
    let layer = &prepared.layer;
    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let handler = Client {
        host: layer.host.clone(),
        port: layer.port,
        known_hosts: prepared.known_hosts.clone(),
    };
    let mut session = russh::client::connect_stream(config, stream, handler)
        .await
        .map_err(|error| format!("SSH handshake failed: {error}"))?;

    let auth = if layer.auth == TunnelAuth::KeyFile {
        let key = prepared
            .key
            .as_ref()
            .ok_or_else(|| "SSH private key was not loaded".to_string())?;
        let hash = session
            .best_supported_rsa_hash()
            .await
            .map_err(|error| format!("SSH negotiation failed: {error}"))?
            .flatten();
        session
            .authenticate_publickey(
                layer.username.clone(),
                russh::keys::PrivateKeyWithHashAlg::new(Arc::clone(key), hash),
            )
            .await
    } else {
        session
            .authenticate_password(layer.username.clone(), layer.password.clone())
            .await
    }
    .map_err(|error| format!("SSH authentication failed: {error}"))?;

    if !auth.success() {
        return Err("SSH authentication was rejected".to_string());
    }

    let channel = session
        .channel_open_direct_tcpip(target.0.to_string(), u32::from(target.1), "127.0.0.1", 0)
        .await
        .map_err(|error| {
            format!(
                "SSH could not forward to {}:{}: {error}",
                target.0, target.1
            )
        })?;

    Ok(Box::new(SshStream {
        stream: channel.into_stream(),
        _session: session,
    }))
}

/// Perform an HTTP `CONNECT` handshake through an HTTP proxy / tunnel.
async fn http_connect(
    mut stream: Stream,
    layer: &TunnelLayer,
    target: (&str, u16),
) -> Result<Stream, String> {
    let authority = format!("{}:{}", target.0, target.1);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if !layer.username.is_empty() {
        let credentials = BASE64.encode(format!("{}:{}", layer.username, layer.password));
        request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("could not send the proxy request: {error}"))?;
    let _ = stream.flush().await;

    // Read the response head (up to the blank line). The proxy may send extra bytes afterwards that
    // belong to the tunnelled stream, so read one byte at a time and stop exactly at the CRLFCRLF.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| format!("could not read the proxy response: {error}"))?;
        if read == 0 {
            return Err("the proxy closed the connection".to_string());
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            return Err("the proxy response header is too large".to_string());
        }
    }

    let status = String::from_utf8_lossy(&head);
    let status_line = status.lines().next().unwrap_or_default();
    if !status_line.contains(" 200") {
        return Err(format!("the proxy refused the connection: {status_line}"));
    }

    Ok(stream)
}

/// Perform a SOCKS5 handshake (no-auth or username/password) and CONNECT to `target`.
async fn socks5_connect(
    mut stream: Stream,
    layer: &TunnelLayer,
    target: (&str, u16),
) -> Result<Stream, String> {
    let use_auth = !layer.username.is_empty();

    // Method negotiation: offer no-auth, plus username/password when credentials are set.
    let greeting: &[u8] = if use_auth {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream
        .write_all(greeting)
        .await
        .map_err(|error| format!("SOCKS5: could not send the greeting: {error}"))?;

    let mut method = [0u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .map_err(|error| format!("SOCKS5: could not read the greeting reply: {error}"))?;
    if method[0] != 0x05 {
        return Err("SOCKS5: unexpected protocol version".to_string());
    }
    match method[1] {
        0x00 => {}
        0x02 => {
            let user = layer.username.as_bytes();
            let password = layer.password.as_bytes();
            if user.len() > 255 || password.len() > 255 {
                return Err("SOCKS5: credentials are too long".to_string());
            }
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user);
            auth.push(password.len() as u8);
            auth.extend_from_slice(password);
            stream
                .write_all(&auth)
                .await
                .map_err(|error| format!("SOCKS5: could not send credentials: {error}"))?;
            let mut reply = [0u8; 2];
            stream
                .read_exact(&mut reply)
                .await
                .map_err(|error| format!("SOCKS5: could not read the auth reply: {error}"))?;
            if reply[1] != 0x00 {
                return Err("SOCKS5: authentication failed".to_string());
            }
        }
        other => {
            return Err(format!("SOCKS5: unsupported auth method {other:#04x}"));
        }
    }

    // CONNECT with a domain name.
    let host = target.0.as_bytes();
    if host.len() > 255 {
        return Err("SOCKS5: host name is too long".to_string());
    }
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.push((target.1 >> 8) as u8);
    request.push((target.1 & 0xff) as u8);
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("SOCKS5: could not send the connect request: {error}"))?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|error| format!("SOCKS5: could not read the connect reply: {error}"))?;
    if head[0] != 0x05 {
        return Err("SOCKS5: unexpected reply version".to_string());
    }
    if head[1] != 0x00 {
        return Err(format!(
            "SOCKS5: the proxy refused the connection (code {})",
            head[1]
        ));
    }

    // Skip the bound address that follows the reply header.
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|error| format!("SOCKS5: could not read the bound address: {error}"))?;
            usize::from(length[0]) + 2
        }
        other => return Err(format!("SOCKS5: unexpected address type {other:#04x}")),
    };
    let mut discard = vec![0u8; skip];
    stream
        .read_exact(&mut discard)
        .await
        .map_err(|error| format!("SOCKS5: could not read the bound address: {error}"))?;

    Ok(stream)
}

#[cfg(test)]
mod tests;
