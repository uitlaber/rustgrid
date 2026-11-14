//! Compatibility with traditional OpenSSL RSA PEM encrypted with AES-256-CBC.
//!
//! russh 0.63 recognises only AES-128-CBC in a legacy `DEK-Info` header and otherwise
//! parses the ciphertext as PKCS#1 DER. Keep the compatibility path here, without
//! changing dependency sources, invoking a subprocess, or rewriting the key file.

use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use russh::keys::{Error, PrivateKey};
use zeroize::Zeroizing;

const BEGIN: &str = "-----BEGIN RSA PRIVATE KEY-----";
const END: &str = "-----END RSA PRIVATE KEY-----";

/// Return `None` for formats handled by russh. A detected AES-256 legacy block is
/// validated strictly and never falls back to treating encrypted bytes as ASN.1.
pub(super) fn decode_aes256_rsa(
    contents: &str,
    passphrase: Option<&str>,
) -> Result<Option<PrivateKey>, Error> {
    let lines: Vec<_> = contents.lines().map(str::trim).collect();
    let Some(start) = lines.iter().position(|line| *line == BEGIN) else {
        return Ok(None);
    };
    let block = &lines[start + 1..];
    let uses_aes256 = block.iter().take_while(|line| **line != END).any(|line| {
        line.strip_prefix("DEK-Info:")
            .is_some_and(|value| value.trim_start().starts_with("AES-256-CBC"))
    });
    if !uses_aes256 {
        return Ok(None);
    }

    let mut encrypted = false;
    let mut iv = None;
    let mut body = String::new();
    let mut in_body = false;
    let mut ended = false;
    for line in block {
        if *line == END {
            ended = true;
            break;
        }
        if line.is_empty() {
            if encrypted && iv.is_some() {
                in_body = true;
            }
            continue;
        }
        if in_body {
            body.push_str(line);
        } else if let Some(value) = line.strip_prefix("Proc-Type:") {
            if encrypted || value.trim() != "4,ENCRYPTED" {
                return Err(Error::CouldNotReadKey);
            }
            encrypted = true;
        } else if let Some(value) = line.strip_prefix("DEK-Info:") {
            let (cipher, hex_iv) = value.trim().split_once(',').ok_or(Error::CouldNotReadKey)?;
            if iv.is_some() || cipher != "AES-256-CBC" {
                return Err(Error::CouldNotReadKey);
            }
            let mut parsed_iv = [0_u8; 16];
            hex::decode_to_slice(hex_iv.trim(), &mut parsed_iv)
                .map_err(|_| Error::CouldNotReadKey)?;
            iv = Some(parsed_iv);
        } else {
            return Err(Error::CouldNotReadKey);
        }
    }
    if !ended || !encrypted || !in_body || body.is_empty() {
        return Err(Error::CouldNotReadKey);
    }
    let iv = iv.ok_or(Error::CouldNotReadKey)?;
    let passphrase = passphrase
        .filter(|value| !value.is_empty())
        .ok_or(Error::KeyIsEncrypted)?;
    let key = derive_key(passphrase.as_bytes(), &iv);
    let mut decrypted = Zeroizing::new(BASE64.decode(body).map_err(|_| Error::CouldNotReadKey)?);
    let plaintext = cbc::Decryptor::<aes::Aes256>::new_from_slices(&key[..], &iv)
        .map_err(|_| Error::CouldNotReadKey)?
        .decrypt_padded_mut::<Pkcs7>(&mut decrypted)
        .map_err(|_| Error::CouldNotReadKey)?;

    // Let the existing RSA parser validate the decrypted key. The compatibility
    // module only implements the legacy container, not RSA or ASN.1 decoding.
    let encoded = Zeroizing::new(BASE64.encode(plaintext));
    let pem = Zeroizing::new(format!("{BEGIN}\n{}\n{END}\n", encoded.as_str()));
    russh::keys::decode_secret_key(&pem, None)
        .map(Some)
        .map_err(|_| Error::CouldNotReadKey)
}

/// OpenSSL traditional PEM uses EVP_BytesToKey(MD5, count=1), with the first
/// eight IV bytes as salt. D_i = MD5(D_(i-1) || passphrase || salt). This legacy
/// KDF is used only to read existing files; no keys are written with it.
/// https://docs.openssl.org/3.6/man3/EVP_BytesToKey/
/// https://docs.openssl.org/master/man3/PEM_read/
fn derive_key(passphrase: &[u8], iv: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut first = md5::Context::new();
    first.consume(passphrase);
    first.consume(&iv[..8]);
    let first = Zeroizing::new(first.finalize().0);
    let mut second = md5::Context::new();
    second.consume(&first[..]);
    second.consume(passphrase);
    second.consume(&iv[..8]);
    let second = Zeroizing::new(second.finalize().0);
    let mut key = Zeroizing::new([0_u8; 32]);
    key[..16].copy_from_slice(&first[..]);
    key[16..].copy_from_slice(&second[..]);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encrypted_block(iv: &str) -> String {
        format!(
            "{BEGIN}\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,{iv}\n\nAAAAAAAAAAAAAAAAAAAAAA==\n{END}\n"
        )
    }

    #[test]
    fn legacy_kdf_matches_openssl_md5_golden_vector() {
        // Independently obtained with OpenSSL/LibreSSL enc -aes-256-cbc -md md5
        // -S 0001020304050607 -P, with the test passphrase supplied on stdin.
        let key = derive_key(
            b"  test key passphrase with spaces  ",
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        );
        assert_eq!(
            hex::encode_upper(&key[..]),
            "48B069D3C733B9BFE391019D9046EAE006ED661EB7D896A7F045F1786E327D5C"
        );
    }

    #[test]
    fn malformed_legacy_iv_is_rejected_before_decryption() {
        for iv in [
            "",
            "001122",
            "00112233445566778899AABBCCDDEEFF00",
            "00112233445566778899AABBCCDDEEFG",
        ] {
            assert!(decode_aes256_rsa(&encrypted_block(iv), Some("test-password")).is_err());
        }
    }

    #[test]
    fn incomplete_or_ambiguous_legacy_headers_are_rejected() {
        let valid = encrypted_block("00112233445566778899AABBCCDDEEFF");
        for malformed in [
            valid.replace("Proc-Type: 4,ENCRYPTED\n", ""),
            valid.replace(END, ""),
            valid.replace(
                "Proc-Type: 4,ENCRYPTED",
                "Proc-Type: 4,ENCRYPTED\nProc-Type: 4,ENCRYPTED",
            ),
            valid.replace("\n\n", "\n"),
        ] {
            assert!(decode_aes256_rsa(&malformed, Some("test-password")).is_err());
        }
    }

    #[test]
    fn malformed_legacy_ciphertext_returns_a_generic_error() {
        let valid = encrypted_block("00112233445566778899AABBCCDDEEFF");
        for ciphertext in ["!invalid-base64!", "AA==", "AAAAAAAAAAAAAAAAAAAAAA=="] {
            let malformed = valid.replace("AAAAAAAAAAAAAAAAAAAAAA==", ciphertext);
            assert!(matches!(
                decode_aes256_rsa(&malformed, Some("test-password")),
                Err(Error::CouldNotReadKey)
            ));
        }
    }

    #[test]
    fn encrypted_legacy_key_requires_a_nonempty_passphrase() {
        let encrypted = encrypted_block("00112233445566778899AABBCCDDEEFF");
        for passphrase in [None, Some("")] {
            assert!(matches!(
                decode_aes256_rsa(&encrypted, passphrase),
                Err(Error::KeyIsEncrypted)
            ));
        }
    }
}
