use rand::Rng;
use rsa::{PublicKey, RSAPrivateKey};

pub mod blind;
mod common;

pub use common::Error;

/// Sign the given blinded message.
pub fn sign<H: digest::Digest + Clone, R: Rng>(
    rng: &mut R,
    priv_key: &RSAPrivateKey,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    let (hashed, _iv) = common::hash_message::<H, RSAPrivateKey>(priv_key, message)?;

    common::sign_hashed(rng, priv_key, &hashed)
}

/// Verifies a signature.
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
