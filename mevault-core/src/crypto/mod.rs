use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng, Payload},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, rand_core::RngCore, SaltString},
    Argon2, Params, PasswordHasher,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

// ── Production constants ────────────────────────────────────────────────────

const ARGON2_MEM_KIB: u32 = 65_536; // 64 MiB
const ARGON2_ITERS: u32 = 3;
const ARGON2_PARA: u32 = 4;

// ── KDF bounds (applied before allocation to untrusted vault-file params) ───

const MIN_MEM_KIB: u32 = 16_384;  // 16 MiB
const MAX_MEM_KIB: u32 = 262_144; // 256 MiB
const MIN_ITERS: u32 = 1;
const MAX_ITERS: u32 = 10;
const MIN_PARA: u32 = 1;
const MAX_PARA: u32 = 16;

// ── KDF profile ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum KdfProfile {
    Argon2idV1,
    /// Deliberately weak params for test speed. Never available in release builds.
    #[cfg(debug_assertions)]
    FastTest,
}

impl KdfProfile {
    pub fn params(&self) -> (u32, u32, u32) {
        match self {
            KdfProfile::Argon2idV1 => (ARGON2_MEM_KIB, ARGON2_ITERS, ARGON2_PARA),
            #[cfg(debug_assertions)]
            KdfProfile::FastTest => (1_024, 1, 1),
        }
    }

    // Minimum allowed mem for blobs decrypted under this profile.
    // FastTest accepts small values so tests can round-trip their own blobs.
    fn min_mem_kib(&self) -> u32 {
        match self {
            KdfProfile::Argon2idV1 => MIN_MEM_KIB,
            #[cfg(debug_assertions)]
            KdfProfile::FastTest => 512,
        }
    }

    fn validate(&self, mem: u32, iters: u32, para: u32) -> Result<()> {
        let min_mem = self.min_mem_kib();
        if mem < min_mem || mem > MAX_MEM_KIB {
            bail!("kdf_mem_kib {mem} outside allowed range [{min_mem}, {MAX_MEM_KIB}]");
        }
        if iters < MIN_ITERS || iters > MAX_ITERS {
            bail!("kdf_iters {iters} outside allowed range [{MIN_ITERS}, {MAX_ITERS}]");
        }
        if para < MIN_PARA || para > MAX_PARA {
            bail!("kdf_parallelism {para} outside allowed range [{MIN_PARA}, {MAX_PARA}]");
        }
        Ok(())
    }
}

// ── Policy ───────────────────────────────────────────────────────────────────

/// Governs which KDF parameters are used for new encryptions and which
/// parameter ranges are accepted from untrusted vault files.
#[derive(Debug, Clone)]
pub struct CryptoPolicy {
    pub kdf_profile: KdfProfile,
}

impl CryptoPolicy {
    pub fn production() -> Self {
        Self { kdf_profile: KdfProfile::Argon2idV1 }
    }

    /// Weak params for unit and integration tests. Only available in debug builds.
    #[cfg(debug_assertions)]
    pub fn fast_test() -> Self {
        Self { kdf_profile: KdfProfile::FastTest }
    }

    fn encrypt_params(&self) -> (u32, u32, u32) {
        self.kdf_profile.params()
    }

    /// Validate KDF params read from an untrusted vault file before any allocation.
    pub fn validate_blob_params(&self, mem: u32, iters: u32, para: u32) -> Result<()> {
        self.kdf_profile.validate(mem, iters, para)
    }
}

// ── EncryptedBlob ────────────────────────────────────────────────────────────

fn default_mem_kib() -> u32 { ARGON2_MEM_KIB }
fn default_iters() -> u32 { ARGON2_ITERS }
fn default_para() -> u32 { ARGON2_PARA }
fn default_aad_version() -> u8 { 0 }

/// Encrypted blob ready for serialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedBlob {
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
    #[serde(default = "default_mem_kib")]
    pub kdf_mem_kib: u32,
    #[serde(default = "default_iters")]
    pub kdf_iters: u32,
    #[serde(default = "default_para")]
    pub kdf_parallelism: u32,
    /// 0 = no AAD (legacy); 1 = vault-name bytes used as AAD.
    #[serde(default = "default_aad_version")]
    pub aad_version: u8,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Encrypt `plaintext` with a password-derived key (Argon2id → AES-256-GCM).
///
/// `aad` binds the ciphertext to a specific context (e.g. vault name) so the
/// blob cannot be transplanted to a different vault and successfully decrypted.
/// KDF parameters are taken from `policy`.
pub fn encrypt(
    plaintext: &[u8],
    password: &SecretString,
    aad: &[u8],
    policy: &CryptoPolicy,
) -> Result<EncryptedBlob> {
    let (mem, iters, para) = policy.encrypt_params();
    let salt = SaltString::generate(&mut OsRng);
    let mut key_bytes = derive_key(password, salt.as_str(), mem, iters, para)?;

    let result = (|| -> Result<EncryptedBlob> {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
        let ciphertext = cipher
            .encrypt(&nonce, Payload { msg: plaintext, aad })
            .map_err(|e| anyhow::anyhow!("AES-GCM encrypt failed: {e}"))?;
        Ok(EncryptedBlob {
            salt: salt.to_string(),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(ciphertext),
            kdf_mem_kib: mem,
            kdf_iters: iters,
            kdf_parallelism: para,
            aad_version: 1,
        })
    })();

    key_bytes.zeroize();
    result
}

/// Decrypt a blob produced by [`encrypt`].
///
/// Returns `Zeroizing<Vec<u8>>` so the plaintext is zeroed when dropped, covering
/// all code paths including early returns via `?`.
///
/// KDF params stored in the blob are validated against `policy` bounds before any
/// Argon2 allocation, preventing a DoS attack via a crafted vault file.
pub fn decrypt(
    blob: &EncryptedBlob,
    password: &SecretString,
    aad: &[u8],
    policy: &CryptoPolicy,
) -> Result<Zeroizing<Vec<u8>>> {
    policy.validate_blob_params(blob.kdf_mem_kib, blob.kdf_iters, blob.kdf_parallelism)?;

    let mut key_bytes = derive_key(password, &blob.salt, blob.kdf_mem_kib, blob.kdf_iters, blob.kdf_parallelism)?;

    let result = (|| -> Result<Vec<u8>> {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let nonce_bytes = B64.decode(&blob.nonce).context("decoding nonce")?;
        if nonce_bytes.len() != 12 {
            bail!("invalid nonce length: expected 12 bytes, got {}", nonce_bytes.len());
        }
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = B64.decode(&blob.ciphertext).context("decoding ciphertext")?;

        let effective_aad: &[u8] = if blob.aad_version >= 1 { aad } else { &[] };

        cipher
            .decrypt(nonce, Payload { msg: ct.as_ref(), aad: effective_aad })
            .map_err(|_| anyhow::anyhow!("decryption failed — wrong password or corrupt vault"))
    })();

    key_bytes.zeroize();
    result.map(Zeroizing::new)
}

// ── Internal ─────────────────────────────────────────────────────────────────

fn derive_key(
    password: &SecretString,
    salt_str: &str,
    mem_kib: u32,
    iters: u32,
    parallelism: u32,
) -> Result<[u8; 32]> {
    let params = Params::new(mem_kib, iters, parallelism, Some(32))
        .map_err(|e| anyhow::anyhow!("building argon2 params: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let salt = argon2::password_hash::Salt::from_b64(salt_str)
        .map_err(|e| anyhow::anyhow!("invalid salt: {e}"))?;

    let hash = argon2
        .hash_password(password.expose_secret().as_bytes(), salt)
        .map_err(|e| anyhow::anyhow!("argon2 hashing failed: {e}"))?;

    let hash_output = hash.hash.context("no hash output from argon2")?;
    let bytes = hash_output.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

// ── Envelope encryption (Phase 2) ───────────────────────────────────────────
//
// The v2 vault format separates key protection (KEK wraps DEK) from payload
// (DEK encrypts secrets).  Argon2 runs exactly once per unlock to derive the
// KEK; subsequent CRUD operations use the cached DEK — no further KDF work.

/// Generate a random 256-bit Data-Encryption Key.
pub fn generate_dek() -> Zeroizing<[u8; 32]> {
    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(dek.as_mut());
    dek
}

/// Derive a Key-Encryption Key from a password using Argon2id.
///
/// The caller is responsible for zeroizing the returned key after use.
/// `mem_kib`, `iters`, `para` are validated against `policy` bounds before
/// any allocation, preventing DoS via a crafted vault file.
pub fn derive_kek(
    password: &SecretString,
    salt_str: &str,
    mem_kib: u32,
    iters: u32,
    para: u32,
    policy: &CryptoPolicy,
) -> Result<Zeroizing<[u8; 32]>> {
    policy.validate_blob_params(mem_kib, iters, para)?;
    let key = derive_key(password, salt_str, mem_kib, iters, para)?;
    Ok(Zeroizing::new(key))
}

/// Wrap (encrypt) a DEK with a KEK using AES-256-GCM.
///
/// Returns `(nonce_b64, ciphertext_b64)`. The AAD should encode the vault
/// identity so a wrapped DEK cannot be moved to a different vault.
pub fn wrap_dek(
    dek: &Zeroizing<[u8; 32]>,
    kek: &Zeroizing<[u8; 32]>,
    aad: &[u8],
) -> Result<(String, String)> {
    let key = Key::<Aes256Gcm>::from_slice(kek.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: dek.as_ref(), aad })
        .map_err(|e| anyhow::anyhow!("key wrap failed: {e}"))?;
    Ok((B64.encode(nonce), B64.encode(ct)))
}

/// Unwrap (decrypt) a DEK from its KEK-encrypted form.
///
/// Returns a `Zeroizing<[u8; 32]>` that is zeroed when dropped.
pub fn unwrap_dek(
    nonce_b64: &str,
    ct_b64: &str,
    kek: &Zeroizing<[u8; 32]>,
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let key = Key::<Aes256Gcm>::from_slice(kek.as_ref());
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes = B64.decode(nonce_b64).context("decoding kek nonce")?;
    if nonce_bytes.len() != 12 {
        bail!("invalid kek nonce length: expected 12, got {}", nonce_bytes.len());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = B64.decode(ct_b64).context("decoding wrapped dek")?;
    let dek_bytes = Zeroizing::new(
        cipher
            .decrypt(nonce, Payload { msg: &ct, aad })
            .map_err(|_| anyhow::anyhow!("key unwrap failed — wrong password or corrupt vault"))?,
    );

    if dek_bytes.len() != 32 {
        bail!("unwrapped DEK has wrong length: expected 32, got {}", dek_bytes.len());
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    dek.copy_from_slice(&dek_bytes);
    Ok(dek)
}

/// Encrypt a vault payload (the secrets JSON) with a DEK using AES-256-GCM.
///
/// Returns `(nonce_b64, ciphertext_b64)`.
pub fn encrypt_payload(plaintext: &[u8], dek: &Zeroizing<[u8; 32]>, aad: &[u8]) -> Result<(String, String)> {
    let key = Key::<Aes256Gcm>::from_slice(dek.as_ref());
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut AesOsRng);
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("payload encrypt failed: {e}"))?;
    Ok((B64.encode(nonce), B64.encode(ct)))
}

/// Decrypt a vault payload with a DEK.
///
/// Returns `Zeroizing<Vec<u8>>` so the plaintext is zeroed on all exit paths.
pub fn decrypt_payload(
    nonce_b64: &str,
    ct_b64: &str,
    dek: &Zeroizing<[u8; 32]>,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = Key::<Aes256Gcm>::from_slice(dek.as_ref());
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes = B64.decode(nonce_b64).context("decoding payload nonce")?;
    if nonce_bytes.len() != 12 {
        bail!("invalid payload nonce length: expected 12, got {}", nonce_bytes.len());
    }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = B64.decode(ct_b64).context("decoding payload ciphertext")?;
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: &ct, aad })
        .map_err(|_| anyhow::anyhow!("payload decryption failed — vault may be corrupt"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Generate a new Argon2id salt string.
pub fn new_kek_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pw(s: &str) -> SecretString {
        SecretString::new(s.to_owned().into())
    }

    #[cfg(debug_assertions)]
    fn policy() -> CryptoPolicy { CryptoPolicy::fast_test() }
    #[cfg(not(debug_assertions))]
    fn policy() -> CryptoPolicy { CryptoPolicy::production() }

    #[test]
    fn round_trip() {
        let p = policy();
        let password = pw("correct-horse-battery-staple");
        let aad = b"my-vault";
        let plaintext = b"hello world, this is a secret payload";
        let blob = encrypt(plaintext, &password, aad, &p).expect("encrypt");
        let recovered = decrypt(&blob, &password, aad, &p).expect("decrypt");
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let p = policy();
        let aad = b"vault";
        let blob = encrypt(b"data", &pw("right-password"), aad, &p).expect("encrypt");
        assert!(decrypt(&blob, &pw("wrong-password"), aad, &p).is_err());
    }

    #[test]
    fn aad_mismatch_fails() {
        let p = policy();
        let blob = encrypt(b"data", &pw("password"), b"vault-a", &p).expect("encrypt");
        assert!(decrypt(&blob, &pw("password"), b"vault-b", &p).is_err(), "wrong AAD must fail");
    }

    #[test]
    fn production_policy_has_correct_params() {
        let (mem, iters, para) = CryptoPolicy::production().kdf_profile.params();
        assert_eq!(mem, ARGON2_MEM_KIB);
        assert_eq!(iters, ARGON2_ITERS);
        assert_eq!(para, ARGON2_PARA);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn fast_test_policy_params_stored_in_blob() {
        let p = CryptoPolicy::fast_test();
        let blob = encrypt(b"x", &pw("password"), b"v", &p).expect("encrypt");
        assert_eq!(blob.kdf_mem_kib, 1_024);
        assert_eq!(blob.kdf_iters, 1);
        assert_eq!(blob.kdf_parallelism, 1);
        assert_eq!(blob.aad_version, 1);
    }

    #[test]
    fn kdf_params_stored_in_blob() {
        let p = policy();
        let blob = encrypt(b"x", &pw("password"), b"v", &p).expect("encrypt");
        assert_eq!(blob.aad_version, 1);
        // params are whatever the policy dictates — just verify they round-trip
        assert!(blob.kdf_mem_kib > 0 && blob.kdf_iters > 0 && blob.kdf_parallelism > 0);
    }

    #[test]
    fn invalid_nonce_length_returns_error_not_panic() {
        let p = policy();
        let mut blob = encrypt(b"data", &pw("password"), b"v", &p).expect("encrypt");
        blob.nonce = B64.encode([0u8; 8]);
        let err = decrypt(&blob, &pw("password"), b"v", &p);
        assert!(err.is_err(), "bad nonce length must return error");
    }

    #[test]
    fn legacy_blob_no_aad_decrypts_with_any_aad_arg() {
        let p = policy();
        let mut blob = encrypt(b"legacy", &pw("password"), &[], &p).expect("encrypt");
        blob.aad_version = 0;
        let result = decrypt(&blob, &pw("password"), b"any-vault-name", &p);
        assert!(result.is_ok(), "legacy blob must decrypt ignoring aad argument");
        assert_eq!(&*result.unwrap(), b"legacy");
    }

    #[test]
    fn kdf_mem_too_low_rejected_by_production_policy() {
        let prod = CryptoPolicy::production();
        // Craft a blob with mem below the production minimum (1 KiB).
        let p = policy();
        let mut blob = encrypt(b"data", &pw("pw"), b"v", &p).expect("encrypt");
        blob.kdf_mem_kib = 1; // well below MIN_MEM_KIB
        assert!(
            decrypt(&blob, &pw("pw"), b"v", &prod).is_err(),
            "mem below minimum must be rejected by production policy"
        );
    }

    #[test]
    fn kdf_mem_too_high_rejected() {
        let p = policy();
        let mut blob = encrypt(b"data", &pw("pw"), b"v", &p).expect("encrypt");
        blob.kdf_mem_kib = MAX_MEM_KIB + 1;
        assert!(decrypt(&blob, &pw("pw"), b"v", &p).is_err(), "mem above max must be rejected");
    }

    #[test]
    fn kdf_iters_zero_rejected() {
        let p = policy();
        let mut blob = encrypt(b"data", &pw("pw"), b"v", &p).expect("encrypt");
        blob.kdf_iters = 0;
        assert!(decrypt(&blob, &pw("pw"), b"v", &p).is_err(), "zero iterations must be rejected");
    }

    #[test]
    fn kdf_iters_too_high_rejected() {
        let p = policy();
        let mut blob = encrypt(b"data", &pw("pw"), b"v", &p).expect("encrypt");
        blob.kdf_iters = MAX_ITERS + 1;
        assert!(decrypt(&blob, &pw("pw"), b"v", &p).is_err(), "iters above max must be rejected");
    }

    #[test]
    fn kdf_parallelism_zero_rejected() {
        let p = policy();
        let mut blob = encrypt(b"data", &pw("pw"), b"v", &p).expect("encrypt");
        blob.kdf_parallelism = 0;
        assert!(decrypt(&blob, &pw("pw"), b"v", &p).is_err(), "zero parallelism must be rejected");
    }

    #[test]
    fn kdf_parallelism_too_high_rejected() {
        let p = policy();
        let mut blob = encrypt(b"data", &pw("pw"), b"v", &p).expect("encrypt");
        blob.kdf_parallelism = MAX_PARA + 1;
        assert!(decrypt(&blob, &pw("pw"), b"v", &p).is_err(), "parallelism above max must be rejected");
    }

    // ── Envelope encryption tests ──────────────────────────────────────────

    #[test]
    fn dek_wrap_unwrap_round_trip() {
        let p = policy();
        let dek = generate_dek();
        let salt = new_kek_salt();
        let (mem, iters, para) = p.kdf_profile.params();
        let kek = derive_kek(&pw("passphrase"), salt.as_str(), mem, iters, para, &p).expect("derive");
        let aad = b"mevault-kek\0vault-id\0vault-name";
        let (nonce, ct) = wrap_dek(&dek, &kek, aad).expect("wrap");
        let recovered = unwrap_dek(&nonce, &ct, &kek, aad).expect("unwrap");
        assert_eq!(*dek, *recovered);
    }

    #[test]
    fn dek_unwrap_wrong_kek_fails() {
        let p = policy();
        let dek = generate_dek();
        let salt = new_kek_salt();
        let (mem, iters, para) = p.kdf_profile.params();
        let kek = derive_kek(&pw("passphrase"), salt.as_str(), mem, iters, para, &p).expect("kek");
        let bad_kek = derive_kek(&pw("wrong"), salt.as_str(), mem, iters, para, &p).expect("bad-kek");
        let aad = b"test-aad";
        let (nonce, ct) = wrap_dek(&dek, &kek, aad).expect("wrap");
        assert!(unwrap_dek(&nonce, &ct, &bad_kek, aad).is_err());
    }

    #[test]
    fn dek_unwrap_wrong_aad_fails() {
        let p = policy();
        let dek = generate_dek();
        let salt = new_kek_salt();
        let (mem, iters, para) = p.kdf_profile.params();
        let kek = derive_kek(&pw("pw"), salt.as_str(), mem, iters, para, &p).expect("kek");
        let (nonce, ct) = wrap_dek(&dek, &kek, b"aad-a").expect("wrap");
        assert!(unwrap_dek(&nonce, &ct, &kek, b"aad-b").is_err());
    }

    #[test]
    fn payload_encrypt_decrypt_round_trip() {
        let dek = generate_dek();
        let plaintext = b"super secret payload content";
        let aad = b"mevault-payload\0vault-id\0vault-name";
        let (nonce, ct) = encrypt_payload(plaintext, &dek, aad).expect("encrypt");
        let recovered = decrypt_payload(&nonce, &ct, &dek, aad).expect("decrypt");
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn payload_decrypt_wrong_dek_fails() {
        let dek = generate_dek();
        let bad_dek = generate_dek();
        let (nonce, ct) = encrypt_payload(b"data", &dek, b"aad").expect("encrypt");
        assert!(decrypt_payload(&nonce, &ct, &bad_dek, b"aad").is_err());
    }

    #[test]
    fn payload_decrypt_wrong_aad_fails() {
        let dek = generate_dek();
        let (nonce, ct) = encrypt_payload(b"data", &dek, b"aad-a").expect("encrypt");
        assert!(decrypt_payload(&nonce, &ct, &dek, b"aad-b").is_err());
    }

    #[test]
    fn generate_dek_is_random() {
        let a = generate_dek();
        let b = generate_dek();
        // Astronomically unlikely to collide.
        assert_ne!(*a, *b);
    }
}
