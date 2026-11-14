use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use russh::keys::ssh_key::{Cipher, Kdf, LineEnding, private::Ed25519Keypair};
use russh::keys::{PrivateKey, PublicKey};

use super::*;

const PASSPHRASE: &str = "  test key passphrase with spaces  ";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn test_private_key(seed: u8) -> PrivateKey {
    PrivateKey::new(
        Ed25519Keypair::from_seed(&[seed; 32]).into(),
        "rustgrid-test-only",
    )
    .unwrap()
}

/// Deterministic keys exist only for local tests and are never real user credentials.
struct TestKey {
    path: PathBuf,
    public: PublicKey,
}

impl TestKey {
    fn new(passphrase: Option<&str>) -> Self {
        static NEXT_KEY: AtomicU64 = AtomicU64::new(0);
        let key = test_private_key(7);
        let public = key.public_key().clone();
        let key = if let Some(passphrase) = passphrase {
            key.encrypt_with(
                Cipher::Aes256Ctr,
                Kdf::Bcrypt {
                    salt: vec![23; 16],
                    rounds: 1,
                },
                42,
                passphrase,
            )
            .unwrap()
        } else {
            key
        };
        let path = std::env::temp_dir().join(format!(
            "rustgrid-tunnel-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_KEY.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).unwrap();
        file.write_all(key.to_openssh(LineEnding::LF).unwrap().as_bytes())
            .unwrap();
        Self { path, public }
    }

    fn layer(&self, passphrase: &str) -> TunnelLayer {
        TunnelLayer {
            host: "127.0.0.1".to_string(),
            username: "tester".to_string(),
            auth: TunnelAuth::KeyFile,
            key_path: self.path.to_string_lossy().into_owned(),
            password: passphrase.to_string(),
            ..TunnelLayer::new(TunnelKind::Ssh)
        }
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct TestKnownHosts(PathBuf);

impl TestKnownHosts {
    fn new(fixture: &TestKey, port: u16, key: Option<&PublicKey>) -> Self {
        let path = fixture.path.with_extension("known_hosts");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        if let Some(key) = key {
            writeln!(file, "[127.0.0.1]:{port} {}", key.to_openssh().unwrap()).unwrap();
        }
        Self(path)
    }
}

impl Drop for TestKnownHosts {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn failure<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("expected an error"),
        Err(error) => error,
    }
}

#[test]
fn unencrypted_key_does_not_need_a_passphrase() {
    let fixture = TestKey::new(None);
    let key = load_ssh_key(&fixture.layer("")).unwrap();
    assert_eq!(key.public_key().key_data(), fixture.public.key_data());
}

#[test]
fn encrypted_key_preserves_spaces_in_its_passphrase_and_is_prepared_once() {
    let fixture = TestKey::new(Some(PASSPHRASE));
    let prepared = prepare_layers(vec![fixture.layer(PASSPHRASE)]).unwrap();
    assert_eq!(
        prepared[0].key.as_ref().unwrap().public_key().key_data(),
        fixture.public.key_data()
    );
    assert!(prepared[0].layer.password.is_empty());
}

#[test]
fn wrong_passphrase_reports_key_unlock_failure_without_revealing_the_secret() {
    let fixture = TestKey::new(Some(PASSPHRASE));
    let error = failure(load_ssh_key(&fixture.layer("incorrect-passphrase")));
    assert!(error.contains("could not unlock the SSH key"), "{error}");
    assert!(!error.contains("incorrect-passphrase"));
    assert!(!error.contains(PASSPHRASE));
}

#[tokio::test]
async fn missing_passphrase_is_reported_before_any_network_connection() {
    let fixture = TestKey::new(Some(PASSPHRASE));
    let mut layer = fixture.layer("");
    layer.host = "must-not-be-resolved.invalid".to_string();
    let error = failure(
        tokio::time::timeout(
            TEST_TIMEOUT,
            Tunnel::start(vec![layer], "127.0.0.1".to_string(), 27017),
        )
        .await
        .unwrap(),
    );
    assert!(error.contains("is encrypted"), "{error}");
    assert!(error.contains("passphrase"), "{error}");
    assert!(!error.contains("must-not-be-resolved"));
}

#[tokio::test]
async fn empty_tunnel_chain_returns_an_error_instead_of_panicking() {
    let error = failure(Tunnel::start(Vec::new(), "127.0.0.1".to_string(), 27017).await);
    assert!(error.contains("empty"));
}

fn http_layer(port: u16) -> TunnelLayer {
    TunnelLayer {
        host: "127.0.0.1".to_string(),
        port,
        ..TunnelLayer::new(TunnelKind::Http)
    }
}

async fn read_connect_request(socket: &mut TcpStream) {
    let mut request = Vec::new();
    loop {
        let byte = socket.read_u8().await.unwrap();
        request.push(byte);
        assert!(request.len() < 4096);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    assert!(request.starts_with(b"CONNECT database.internal:27017 HTTP/1.1\r\n"));
}

#[tokio::test]
async fn initial_proxy_failure_is_returned_to_the_driver() {
    let proxy = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = proxy.accept().await.unwrap();
        read_connect_request(&mut socket).await;
        socket
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await
            .unwrap();
    });
    let error = failure(
        tokio::time::timeout(
            TEST_TIMEOUT,
            Tunnel::start(vec![http_layer(port)], "database.internal".into(), 27017),
        )
        .await
        .unwrap(),
    );
    assert!(
        error.contains("407 Proxy Authentication Required"),
        "{error}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn stalled_proxy_handshake_is_bounded() {
    let proxy = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (_socket, _) = proxy.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let prepared = prepare_layers(vec![http_layer(port)]).unwrap();
    let error = failure(
        open_stream_with_timeout(
            &prepared,
            ("database.internal", 27017),
            Duration::from_millis(50),
        )
        .await,
    );
    assert!(error.contains("timed out"), "{error}");
    server.abort();
}

#[tokio::test]
async fn forwards_multiple_connections_and_reuses_the_preflight_stream() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let proxy = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for index in 0..2u8 {
                let (mut socket, _) = proxy.accept().await.unwrap();
                read_connect_request(&mut socket).await;
                socket
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .unwrap();
                // A server-first greeting must survive preflight and reach the first client.
                socket.write_u8(index).await.unwrap();
                let mut data = [0u8; 4];
                socket.read_exact(&mut data).await.unwrap();
                assert_eq!(&data, b"ping");
                socket.write_all(b"pong").await.unwrap();
            }
        });
        let tunnel = Tunnel::start(vec![http_layer(port)], "database.internal".into(), 27017)
            .await
            .unwrap();
        for index in 0..2u8 {
            let mut client = TcpStream::connect(("127.0.0.1", tunnel.local_port()))
                .await
                .unwrap();
            assert_eq!(client.read_u8().await.unwrap(), index);
            client.write_all(b"ping").await.unwrap();
            let mut data = [0u8; 4];
            client.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"pong");
        }
        server.await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_tunnel_closes_existing_forwarded_connections() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let proxy = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = proxy.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = proxy.accept().await.unwrap();
            read_connect_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nready")
                .await
                .unwrap();
            let mut byte = [0u8; 1];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        });
        let tunnel = Tunnel::start(vec![http_layer(port)], "database.internal".into(), 27017)
            .await
            .unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", tunnel.local_port()))
            .await
            .unwrap();
        let mut greeting = [0u8; 5];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"ready");
        drop(tunnel);
        server.await.unwrap();
    })
    .await
    .unwrap();
}

struct SshEcho {
    public_key: PublicKey,
}

impl russh::server::Handler for SshEcho {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        assert_eq!(user, "tester");
        assert_eq!(key.key_data(), self.public_key.key_data());
        Ok(russh::server::Auth::Accept)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        assert_eq!(host_to_connect, "database.internal");
        assert_eq!(port_to_connect, 27017);
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let mut data = [0u8; 4];
            stream.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        Ok(())
    }
}

#[tokio::test]
async fn encrypted_key_authenticates_and_forwards_over_real_ssh() {
    tokio::time::timeout(TEST_TIMEOUT, async {
        let fixture = TestKey::new(Some(PASSPHRASE));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let mut layer = fixture.layer(PASSPHRASE);
        layer.port = listener.local_addr().unwrap().port();
        let known_hosts =
            TestKnownHosts::new(&fixture, layer.port, Some(test_private_key(9).public_key()));
        let handler = SshEcho {
            public_key: fixture.public.clone(),
        };
        let server = tokio::spawn(async move {
            let config = Arc::new(russh::server::Config {
                keys: vec![test_private_key(9)],
                auth_rejection_time: Duration::ZERO,
                ..Default::default()
            });
            let (socket, _) = listener.accept().await.unwrap();
            let session = russh::server::run_stream(config, socket, handler)
                .await
                .unwrap();
            let _ = session.await;
        });
        let tunnel = Tunnel::start_with_known_hosts(
            vec![layer],
            "database.internal".into(),
            27017,
            Some(known_hosts.0.clone()),
        )
        .await
        .unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", tunnel.local_port()))
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut data = [0u8; 4];
        client.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"pong");
        drop(client);
        drop(tunnel);
        server.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_ssh_host_key_is_rejected_without_changing_known_hosts() {
    use russh::client::Handler as _;

    let fixture = TestKey::new(None);
    let known_hosts = TestKnownHosts::new(&fixture, 2222, None);
    let mut client = Client {
        host: "127.0.0.1".into(),
        port: 2222,
        known_hosts: Some(known_hosts.0.clone()),
    };
    let key = PublicKey::new(test_private_key(9).public_key().key_data().clone(), "");
    let error = client.check_server_key(&key.into()).await.unwrap_err();
    assert!(error.to_string().contains("is unknown"), "{error}");
    assert!(error.to_string().contains("system ssh"), "{error}");
    assert!(std::fs::read_to_string(&known_hosts.0).unwrap().is_empty());
}

#[tokio::test]
async fn changed_ssh_host_key_is_rejected_without_replacing_the_trusted_key() {
    use russh::client::Handler as _;

    let fixture = TestKey::new(None);
    let known_hosts = TestKnownHosts::new(&fixture, 2222, Some(test_private_key(9).public_key()));
    let before = std::fs::read_to_string(&known_hosts.0).unwrap();
    let mut client = Client {
        host: "127.0.0.1".into(),
        port: 2222,
        known_hosts: Some(known_hosts.0.clone()),
    };
    let key = PublicKey::new(test_private_key(11).public_key().key_data().clone(), "");
    let error = client.check_server_key(&key.into()).await.unwrap_err();
    assert!(error.to_string().contains("has changed"), "{error}");
    assert!(error.to_string().contains("Connection refused"), "{error}");
    assert_eq!(std::fs::read_to_string(&known_hosts.0).unwrap(), before);
}

#[tokio::test]
async fn revoked_ssh_host_key_is_rejected_even_when_it_also_has_a_trusted_entry() {
    use russh::client::Handler as _;

    let fixture = TestKey::new(None);
    let host_key = test_private_key(9);
    let known_hosts = TestKnownHosts::new(&fixture, 2222, Some(host_key.public_key()));
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&known_hosts.0)
        .unwrap();
    writeln!(
        file,
        "@revoked * {}",
        host_key.public_key().to_openssh().unwrap()
    )
    .unwrap();
    let before = std::fs::read_to_string(&known_hosts.0).unwrap();
    let mut client = Client {
        host: "127.0.0.1".into(),
        port: 2222,
        known_hosts: Some(known_hosts.0.clone()),
    };
    let key = PublicKey::new(host_key.public_key().key_data().clone(), "");
    let error = client.check_server_key(&key.into()).await.unwrap_err();
    assert!(error.to_string().contains("is revoked"), "{error}");
    assert_eq!(std::fs::read_to_string(&known_hosts.0).unwrap(), before);
}

#[tokio::test]
async fn ssh_host_certificate_is_not_treated_as_a_trusted_raw_key() {
    use russh::client::Handler as _;
    use russh::keys::ssh_key::certificate::{Builder, CertType};

    let fixture = TestKey::new(None);
    let host_key = test_private_key(9);
    let known_hosts = TestKnownHosts::new(&fixture, 2222, Some(host_key.public_key()));
    let mut builder = Builder::new(
        vec![0; 32],
        host_key.public_key().key_data().clone(),
        0,
        u64::MAX,
    )
    .unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.valid_principal("127.0.0.1").unwrap();
    let certificate = builder.sign(&test_private_key(11)).unwrap();
    let mut client = Client {
        host: "127.0.0.1".into(),
        port: 2222,
        known_hosts: Some(known_hosts.0.clone()),
    };
    let error = client
        .check_server_key(&certificate.into())
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("host certificates are not supported"),
        "{error}"
    );
}
