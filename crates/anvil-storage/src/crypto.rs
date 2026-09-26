//! Authenticated encryption primitives (reviewed RustCrypto crates only).
//!
//! * AEAD: XChaCha20-Poly1305 with a random 192-bit nonce per message.
//! * KDF: Argon2id with parameters stored beside the wrapped key.
//!
//! Envelope layout: `version(1) || nonce(24) || ciphertext+tag`.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

pub const ENVELOPE_V1: u8 = 1;
pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Largest Argon2id memory cost (KiB) a stored or received key may ask for.
pub const MAX_KDF_MEMORY_KIB: u32 = 256 * 1024;
/// Largest Argon2id pass count a stored or received key may ask for.
pub const MAX_KDF_ITERATIONS: u32 = 10;
/// Largest Argon2id lane count a stored or received key may ask for.
pub const MAX_KDF_PARALLELISM: u32 = 4;
/// Largest memory x passes product (KiB-passes) a stored or received key may
/// ask for: 1 GiB in total, e.g. 256 MiB for 4 passes. Profiles and exports
/// use 64 MiB for 3 passes.
pub const MAX_KDF_WORK: u64 = 1024 * 1024;
/// Shortest salt a stored or received key may name.
pub const MIN_SALT_LEN: usize = 8;
/// Longest salt a stored or received key may name.
pub const MAX_SALT_LEN: usize = 64;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("decryption failed: wrong key or the data was modified")]
    Authentication,
    #[error("unsupported envelope version {0}")]
    Version(u8),
    #[error("malformed envelope")]
    Malformed,
    #[error("key derivation failed: {0}")]
    Kdf(String),
}

/// A 256-bit key that zeroizes on drop.
#[derive(Clone)]
pub struct Key(Zeroizing<[u8; KEY_LEN]>);

impl Key {
    pub fn random() -> Self {
        let mut k = [0u8; KEY_LEN];
        rand::fill(&mut k);
        let key = Key(Zeroizing::new(k));
        k.zeroize();
        key
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, CryptoError> {
        if b.len() != KEY_LEN {
            return Err(CryptoError::Malformed);
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(b);
        Ok(Key(Zeroizing::new(k)))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(‹redacted›)")
    }
}

pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("32-byte key");
    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce);
    let ct = cipher.encrypt((&nonce).into(), Payload { msg: plaintext, aad }).expect("encryption cannot fail for in-memory buffers");
    let mut out = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    out.push(ENVELOPE_V1);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &Key, aad: &[u8], envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if envelope.len() < 1 + NONCE_LEN + 16 {
        return Err(CryptoError::Malformed);
    }
    if envelope[0] != ENVELOPE_V1 {
        return Err(CryptoError::Version(envelope[0]));
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).expect("32-byte key");
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&envelope[1..1 + NONCE_LEN]);
    cipher
        .decrypt((&nonce).into(), Payload { msg: &envelope[1 + NONCE_LEN..], aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::Authentication)
}

/// Argon2id parameters recorded next to every passphrase-wrapped key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    /// Memory cost in KiB.
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlgorithm {
    Argon2id,
}

impl KdfParams {
    /// Interactive-unlock defaults (64 MiB, 3 passes).
    pub fn interactive() -> Self {
        KdfParams { algorithm: KdfAlgorithm::Argon2id, m_cost: 64 * 1024, t_cost: 3, p_cost: 1 }
    }

    /// Cheap parameters for tests only.
    pub fn testing() -> Self {
        KdfParams { algorithm: KdfAlgorithm::Argon2id, m_cost: 1024, t_cost: 1, p_cost: 1 }
    }

    /// Refuse Argon2id costs outside the bounds above, with the reason. The
    /// costs are read before anything they protect can authenticate, so
    /// they are checked before any derivation.
    pub fn check_bounds(&self) -> Result<(), String> {
        if !(1..=MAX_KDF_ITERATIONS).contains(&self.t_cost) {
            return Err(format!("{} passes; allowed 1 to {MAX_KDF_ITERATIONS}", self.t_cost));
        }
        if !(1..=MAX_KDF_PARALLELISM).contains(&self.p_cost) {
            return Err(format!("{} lanes; allowed 1 to {MAX_KDF_PARALLELISM}", self.p_cost));
        }
        // Argon2 needs at least 8 KiB per lane.
        let min_memory = 8 * self.p_cost;
        if !(min_memory..=MAX_KDF_MEMORY_KIB).contains(&self.m_cost) {
            return Err(format!("{} KiB of memory; allowed {min_memory} to {MAX_KDF_MEMORY_KIB} KiB", self.m_cost));
        }
        let work = u64::from(self.m_cost) * u64::from(self.t_cost);
        if work > MAX_KDF_WORK {
            return Err(format!("{} KiB for {} passes exceeds the budget of {MAX_KDF_WORK} KiB-passes", self.m_cost, self.t_cost));
        }
        Ok(())
    }
}

/// Refuse a salt whose length is outside [`MIN_SALT_LEN`] to [`MAX_SALT_LEN`],
/// with the reason.
pub fn check_salt(salt: &[u8]) -> Result<(), String> {
    if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()) {
        return Err(format!("{}-byte salt; allowed {MIN_SALT_LEN} to {MAX_SALT_LEN}", salt.len()));
    }
    Ok(())
}

pub fn derive(passphrase: &[u8], salt: &[u8], p: &KdfParams) -> Result<Key, CryptoError> {
    let params = Params::new(p.m_cost, p.t_cost, p.p_cost, Some(KEY_LEN)).map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon.hash_password_into(passphrase, salt, out.as_mut()).map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Key::from_bytes(out.as_ref())
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::fill(&mut v[..]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let k = Key::random();
        let e = seal(&k, b"request:1", b"secret body");
        assert_eq!(open(&k, b"request:1", &e).unwrap().as_slice(), b"secret body");
        assert_eq!(open(&k, b"request:2", &e), Err(CryptoError::Authentication), "records cannot be swapped");
        let mut tampered = e.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(open(&k, b"request:1", &tampered), Err(CryptoError::Authentication));
        assert_eq!(open(&Key::random(), b"request:1", &e), Err(CryptoError::Authentication));
    }

    #[test]
    fn kdf_is_deterministic_per_salt() {
        let p = KdfParams::testing();
        let a = derive(b"pw", b"saltsaltsaltsalt", &p).unwrap();
        let b = derive(b"pw", b"saltsaltsaltsalt", &p).unwrap();
        let c = derive(b"pw", b"othersaltothersalt", &p).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }
}
