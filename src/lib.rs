//! RSA-FDH is a is provably secure blind-signing signature scheme that uses RSA and a full domain hash.
//!
//! This crate implements two RSA-FDH signature schemes:
//!
//! 1. A regular signature scheme with Full Domain Hash (FDH) padding.
//!
//! 2. A blind signature scheme that that supports blind-signing to keep the message being signed secret from the signer.
//!
//! ### Regular signature scheme example
//!
//! ```
//! use rsa::{RSAPrivateKey, RSAPublicKey};
//! use sha2::{Sha256, Digest};
//!
//! // Set up rng and message
//! let mut rng = rand::thread_rng();;
//! let message = b"NEVER GOING TO GIVE YOU UP";
//!
//! // Create the keys
//! let signer_priv_key = RSAPrivateKey::new(&mut rng, 2048).unwrap();
//! let signer_pub_key: RSAPublicKey = signer_priv_key.clone().into();
//!
//! // Apply a standard digest to the message
//! let mut hasher = Sha256::new();
//! hasher.input(message);
//! let digest = hasher.result();
//!
//! // Obtain a signture
//! let signature = rsa_fdh::sign::<Sha256, _>(&mut rng, &signer_priv_key, &digest).unwrap();
//!
//! // Verify the signature
//! let ok = rsa_fdh::verify::<Sha256, _>(&signer_pub_key, &digest, &signature);
//! assert!(ok.is_ok());
//! ```

use rand::Rng;
use rsa::{PublicKey, RSAPrivateKey};

pub mod blind;
mod common;

pub use common::Error;

/// Sign a message.
///
/// Generally the message should be hashed by the requester before being sent to the signer.
/// The signer will apply RSA-FDH padding before singing the message.
/// The resulting signature is not a blind signature.
pub fn sign<H: digest::Digest + Clone, R: Rng>(
    rng: &mut R,
    priv_key: &RSAPrivateKey,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    let (hashed, _iv) = common::hash_message::<H, RSAPrivateKey>(priv_key, message)?;

    common::sign_hashed(rng, priv_key, &hashed)
}

/// Verify a signature.
///
/// Generally the message should be hashed before verifying the digest against the provided signature.
pub fn verify<H: digest::Digest + Clone, K: PublicKey>(
    pub_key: &K,
    message: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    // Apply FDH
    let (hashed, _iv) = common::hash_message::<H, K>(pub_key, message)?;

    common::verify_hashed(pub_key, &hashed, sig)
}

#[cfg(test)]
mod tests {
    use crate as rsa_fdh;
    use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};
    use sha2::{Digest, Sha256};

    #[test]
    fn regular_test() -> Result<(), rsa_fdh::Error> {
        // Stage 1: Setup
        // --------------
        let mut rng = rand::thread_rng();
        let message = b"NEVER GOING TO GIVE YOU UP";

        // Hash the message normally
        let mut hasher = Sha256::new();
        hasher.input(message);
        let digest = hasher.result();

        // Create the keys
        let signer_priv_key = RSAPrivateKey::new(&mut rng, 256).unwrap();
        let signer_pub_key =
            RSAPublicKey::new(signer_priv_key.n().clone(), signer_priv_key.e().clone()).unwrap();

        // Do this a bunch so that we get a good sampling of possibe digests.
        for _ in 0..500 {
            let signature = rsa_fdh::sign::<Sha256, _>(&mut rng, &signer_priv_key, &digest)?;
            rsa_fdh::verify::<Sha256, _>(&signer_pub_key, &digest, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn error_test() -> Result<(), rsa_fdh::Error> {
        let mut rng = rand::thread_rng();
        let message = b"NEVER GOING TO GIVE YOU UP";

        // Hash the message normally
        let mut hasher = Sha256::new();
        hasher.input(message);
        let digest = hasher.result();

        // Create the keys
        let key_1 = RSAPrivateKey::new(&mut rng, 256).unwrap();
        let signature_1 = rsa_fdh::sign::<Sha256, _>(&mut rng, &key_1, &digest)?;

        let key_2 = RSAPrivateKey::new(&mut rng, 512).unwrap();
        let signature_2 = rsa_fdh::sign::<Sha256, _>(&mut rng, &key_2, &digest)?;

        // Assert that signatures are different
        assert!(signature_1 != signature_2);

        // Assert that they don't cross validate
        assert!(rsa_fdh::verify::<Sha256, _>(&key_1, &signature_2, &digest).is_err());
        assert!(rsa_fdh::verify::<Sha256, _>(&key_2, &signature_1, &digest).is_err());

        Ok(())
    }
}
