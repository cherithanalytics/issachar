use argon2::{Algorithm, Argon2, Params, Version};

/// Argon2id security level — selects memory, iteration, and parallelism constants.
pub enum SecurityLevel {
    /// Password verification at login time (~300–500 ms, OWASP T3, 64 MiB).
    Interactive,
    /// Long-term key derivation from low-entropy passwords (~5–10 s, 1 GiB).
    Offline,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("argon2: {0}")]
    Argon2(argon2::Error),
}

// Interactive: m=65536 KiB, t=3, p=4  (OWASP T3)
// Offline:     m=1048576 KiB, t=4, p=4
fn params(level: SecurityLevel) -> Result<Params, Error> {
    let (m, t, p) = match level {
        SecurityLevel::Interactive => (65_536, 3, 4),
        SecurityLevel::Offline => (1_048_576, 4, 4),
    };
    Params::new(m, t, p, Some(64)).map_err(Error::Argon2)
}

/// Derive a 64-byte key from `password` and `salt` using Argon2id.
///
/// Salt must be ≥ 8 bytes; 16 random bytes is recommended.
pub fn derive(password: &[u8], salt: &[u8], level: SecurityLevel) -> Result<[u8; 64], Error> {
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params(level)?);
    let mut out = [0u8; 64];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(Error::Argon2)?;
    Ok(out)
}

/// Verify `password` against a previously derived key, using constant-time comparison.
///
/// Salt must be ≥ 8 bytes; 16 random bytes is recommended.
pub fn verify(
    password: &[u8],
    salt: &[u8],
    expected: &[u8; 64],
    level: SecurityLevel,
) -> Result<bool, Error> {
    let derived = derive(password, salt, level)?;
    Ok(crate::timing_safe_eq(&derived, expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &[u8] = b"correct-horse-battery";
    const SALT: &[u8] = b"saltsaltsalt1234";

    #[test]
    fn derive_is_deterministic() {
        let a = derive(PW, SALT, SecurityLevel::Interactive).unwrap();
        let b = derive(PW, SALT, SecurityLevel::Interactive).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn verify_accepts_correct_password() {
        let key = derive(PW, SALT, SecurityLevel::Interactive).unwrap();
        assert!(verify(PW, SALT, &key, SecurityLevel::Interactive).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let key = derive(PW, SALT, SecurityLevel::Interactive).unwrap();
        assert!(!verify(b"wrong-password--", SALT, &key, SecurityLevel::Interactive).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_salt() {
        let key = derive(PW, SALT, SecurityLevel::Interactive).unwrap();
        assert!(!verify(PW, b"wrongsaltwronsal", &key, SecurityLevel::Interactive).unwrap());
    }

    #[test]
    fn short_salt_is_an_error() {
        assert!(derive(PW, b"short", SecurityLevel::Interactive).is_err());
    }

    #[test]
    fn different_passwords_produce_different_keys() {
        let a = derive(PW, SALT, SecurityLevel::Interactive).unwrap();
        let b = derive(b"different-passw!", SALT, SecurityLevel::Interactive).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let a = derive(PW, SALT, SecurityLevel::Interactive).unwrap();
        let b = derive(PW, b"othersaltother12", SecurityLevel::Interactive).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    #[ignore = "allocates 1 GiB — run explicitly with `cargo test -- --ignored`"]
    fn offline_is_deterministic() {
        let a = derive(PW, SALT, SecurityLevel::Offline).unwrap();
        let b = derive(PW, SALT, SecurityLevel::Offline).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    #[ignore = "allocates 1 GiB — run explicitly with `cargo test -- --ignored`"]
    fn offline_differs_from_interactive() {
        let interactive = derive(PW, SALT, SecurityLevel::Interactive).unwrap();
        let offline = derive(PW, SALT, SecurityLevel::Offline).unwrap();
        assert_ne!(interactive, offline);
    }
}
