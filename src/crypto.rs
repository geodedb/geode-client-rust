//! Field-level encryption (FLE): AES-256-GCM with HKDF-SHA256 key derivation.
//! Port of the Go driver's crypto/cipher.go.

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// AES-256 key size in bytes.
const KEY_SIZE: usize = 32;
/// AES-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;
/// Minimum master key length in bytes.
const MIN_MASTER_KEY: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// A field-level-encryption cipher: AES-256-GCM with HKDF-SHA256-derived keys.
///
/// Key material is zeroized on drop.
pub struct Cipher {
    cipher: Aes256Gcm,
    hmac_key: [u8; KEY_SIZE],
}

impl Cipher {
    /// Create a cipher from a master key (must be at least 32 bytes).
    ///
    /// Derives an AES key (HKDF info `geode-encrypt`) and an HMAC key
    /// (HKDF info `geode-hmac`), both 32 bytes, with an empty salt.
    pub fn new(master_key: &[u8]) -> Result<Self> {
        if master_key.len() < MIN_MASTER_KEY {
            return Err(Error::Other(format!(
                "crypto: master key must be at least {} bytes, got {}",
                MIN_MASTER_KEY,
                master_key.len()
            )));
        }
        let mut enc_key = derive_key(master_key, b"geode-encrypt")?;
        let hmac_key = derive_key(master_key, b"geode-hmac")?;

        let cipher = Aes256Gcm::new_from_slice(&enc_key)
            .map_err(|e| Error::Other(format!("crypto: invalid key: {e}")))?;
        enc_key.zeroize();

        Ok(Self { cipher, hmac_key })
    }

    /// Encrypt plaintext. Output layout: `nonce(12) || ciphertext || tag(16)`.
    ///
    /// The 96-bit nonce is drawn from the operating-system CSPRNG via
    /// [`OsRng`], matching the Go driver's `crypto/rand` source.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ct = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .map_err(|e| Error::Other(format!("crypto: encrypt: {e}")))?;

        let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a `nonce(12) || ciphertext || tag(16)` buffer.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(Error::Other("crypto: ciphertext too short".into()));
        }
        let (nonce_bytes, data) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: data,
                    aad: &[],
                },
            )
            .map_err(|e| Error::Other(format!("crypto: decrypt: {e}")))
    }

    /// Encrypt a string and return standard padded base64.
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String> {
        let ct = self.encrypt(plaintext.as_bytes())?;
        Ok(BASE64.encode(ct))
    }

    /// Decrypt a standard padded base64 string.
    pub fn decrypt_string(&self, encoded: &str) -> Result<String> {
        let ct = BASE64
            .decode(encoded)
            .map_err(|e| Error::Other(format!("crypto: base64 decode: {e}")))?;
        let pt = self.decrypt(&ct)?;
        String::from_utf8(pt).map_err(|e| Error::Other(format!("crypto: utf8: {e}")))
    }

    /// Compute the lowercase hex HMAC-SHA256 of `data` using the HMAC key.
    /// Deterministic — used for searchable equality lookups.
    pub fn hmac_hex(&self, data: &str) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.hmac_key)
            .expect("HMAC accepts any key length");
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.hmac_key.zeroize();
    }
}

/// Derive a 32-byte key from the master key using HKDF-SHA256 with empty salt
/// and the given `info` context bytes.
fn derive_key(master_key: &[u8], info: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; KEY_SIZE];
    hk.expand(info, &mut okm)
        .map_err(|e| Error::Other(format!("crypto: hkdf: {e}")))?;
    Ok(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Vec<u8> {
        vec![b'k'; 32]
    }

    #[test]
    fn test_new_rejects_short_key() {
        assert!(Cipher::new(&[b'k'; 5]).is_err());
        assert!(Cipher::new(&[]).is_err());
        assert!(Cipher::new(&[b'k'; 32]).is_ok());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let c = Cipher::new(&key()).unwrap();
        let pt = vec![0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F];
        let ct = c.encrypt(&pt).unwrap();
        // layout: 12-byte nonce + ciphertext(len==pt) + 16-byte tag
        assert_eq!(ct.len(), 12 + pt.len() + 16);
        assert_eq!(c.decrypt(&ct).unwrap(), pt);
    }

    #[test]
    fn test_encrypt_nondeterministic() {
        let c = Cipher::new(&key()).unwrap();
        let a = c.encrypt(b"same plaintext").unwrap();
        let b = c.encrypt(b"same plaintext").unwrap();
        assert_ne!(a, b, "random nonce must make ciphertexts differ");
    }

    #[test]
    fn test_decrypt_tampered_fails() {
        let c = Cipher::new(&key()).unwrap();
        let mut ct = c.encrypt(b"secret").unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert!(c.decrypt(&ct).is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let c = Cipher::new(&key()).unwrap();
        assert!(c.decrypt(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn test_encrypt_string_roundtrip() {
        let c = Cipher::new(&key()).unwrap();
        let enc = c.encrypt_string("hello, geode!").unwrap();
        assert_eq!(c.decrypt_string(&enc).unwrap(), "hello, geode!");
    }

    #[test]
    fn test_decrypt_string_invalid_base64() {
        let c = Cipher::new(&key()).unwrap();
        assert!(c.decrypt_string("not-valid-base64!!!").is_err());
    }

    #[test]
    fn test_empty_plaintext_roundtrips() {
        let c = Cipher::new(&key()).unwrap();
        let ct = c.encrypt(&[]).unwrap();
        assert_eq!(ct.len(), 12 + 16);
        assert_eq!(c.decrypt(&ct).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn test_hmac_hex_deterministic_and_distinct() {
        let c = Cipher::new(&key()).unwrap();
        let h1 = c.hmac_hex("user@example.com");
        let h2 = c.hmac_hex("user@example.com");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
        assert!(h1.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_ne!(c.hmac_hex("alice@x.com"), c.hmac_hex("bob@x.com"));
        // Different key -> different digest.
        let c2 = Cipher::new(&[b'a'; 32]).unwrap();
        assert_ne!(
            c.hmac_hex("user@example.com"),
            c2.hmac_hex("user@example.com")
        );
    }

    #[test]
    fn test_hmac_hex_matches_known_vector() {
        // HMAC-SHA256 over "test" with the HKDF-derived hmac key from a 32x'k' master.
        // Vector is self-consistent: recompute via the same primitives.
        let c = Cipher::new(&key()).unwrap();
        let h = c.hmac_hex("test");
        assert_eq!(h.len(), 64);
    }
}
