use failure::Fail;
use fdh::{FullDomainHash, Input, VariableOutput};
use num_bigint_dig::BigUint;
use rand::Rng;
use rsa::errors::Error as RSAError;
use rsa::internals;
use rsa::{PublicKey, RSAPrivateKey};
use subtle::ConstantTimeEq;

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "rsa-fdh: digest big-endian numeric value is too large")]
    DigestTooLarge,
    #[fail(display = "rsa-fdh: digest is incorrectly sized")]
    DigestIncorrectSize,
    #[fail(display = "rsa-fdh: verification failed")]
    Verification,
    #[fail(display = "rsa-fdh: public key modulus is too large")]
    ModulusTooLarge,
    #[fail(display = "rsa-fdh: rsa error: {}", 0)]
    RSAError(RSAError),
}

pub fn sign<R: Rng>(
    rng: &mut R,
    priv_key: &RSAPrivateKey,
    hashed: &[u8],
) -> Result<Vec<u8>, Error> {
    if priv_key.size() < hashed.len() {
        return Err(Error::DigestIncorrectSize);
    }

    let n = priv_key.n();
    let m = BigUint::from_bytes_be(&hashed);

    if m >= *n {
        return Err(Error::DigestTooLarge);
    }

    let c = internals::decrypt_and_check(Some(rng), priv_key, &m)
        .map_err(|err| Error::RSAError(err))?
        .to_bytes_be();

    Ok(c)
}

/// Verifies an RSA PKCS#1 v1.5 signature.
pub fn verify<K: PublicKey>(pub_key: &K, hashed: &[u8], sig: &[u8]) -> Result<(), Error> {
    if hashed.len() != pub_key.size() {
        return Err(Error::Verification);
    }

    let n = pub_key.n();
    let m = BigUint::from_bytes_be(&hashed);
    if &m >= n {
        return Err(Error::Verification);
    }

    let c = BigUint::from_bytes_be(sig);
    let m = internals::encrypt(pub_key, &c).to_bytes_be();

    // Constant time compare message with hashed
    let ok = m.ct_eq(hashed);

    if ok.unwrap_u8() != 1 {
        return Err(Error::Verification);
    }

    Ok(())
}

/// Blind the given digest, returning the blinded digest and the unblinding factor.
pub fn blind<R: Rng, P: PublicKey>(rng: &mut R, pub_key: P, digest: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let c = BigUint::from_bytes_be(digest);
    let (c, unblinder) = internals::blind::<R, P>(rng, &pub_key, &c);
    (c.to_bytes_be(), unblinder.to_bytes_be())
}

/// Unblind the given signature, producing a signature that also signs the unblided digest.
pub fn unblind(pub_key: impl PublicKey, blinded_sig: &[u8], unblinder: &[u8]) -> Vec<u8> {
    let blinded_sig = BigUint::from_bytes_be(blinded_sig);
    let unblinder = BigUint::from_bytes_be(unblinder);
    let unblinded = internals::unblind(pub_key, &blinded_sig, &unblinder);
    unblinded.to_bytes_be()
}

/// Convenience function for hashing
pub fn hash_message<H: digest::Digest + Clone, R: Rng, P: PublicKey>(
    rng: &mut R,
    signer_public_key: &P,
    message: &[u8],
) -> Result<(Vec<u8>, u32), Error> {
    let size = signer_public_key.size();
    let mut hasher = FullDomainHash::<H>::new(size).unwrap(); // will never panic.
    hasher.input(message);

    // Append the hash of the message as anti-homomorphic error correction.
    let mut append_hasher = H::new();
    append_hasher.input(message);
    hasher.input(append_hasher.result());

    let iv: u32 = rng.gen();
    let (digest, iv) = hasher
        .results_under(iv, signer_public_key.n())
        .map_err(|_| Error::ModulusTooLarge)?;

    Ok((digest, iv))
}

/// Convenience function for hashing a message with an initilization vector
pub fn hash_message_with_iv<H: digest::Digest + Clone, P: PublicKey>(
    iv: u32,
    signer_public_key: &P,
    message: &[u8],
) -> Vec<u8> {
    let size = signer_public_key.size();
    let mut hasher = FullDomainHash::<H>::with_iv(size, iv);
    hasher.input(message);

    // Append the hash of the message as anti-homomorphic error correction.
    let mut append_hasher = H::new();
    append_hasher.input(message);
    hasher.input(append_hasher.result());

    hasher.vec_result()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use fdh::{FullDomainHash, Input, VariableOutput};
    use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};
    use sha2::Sha512;

    #[test]
    fn example_test() -> Result<(), Error> {
        // Stage 1: Setup
        // --------------
        let mut rng = rand::thread_rng();
        let message = b"NEVER GOING TO GIVE YOU UP";

        // Create the keys
        let signer_priv_key = RSAPrivateKey::new(&mut rng, 256).unwrap();
        let signer_pub_key =
            RSAPublicKey::new(signer_priv_key.n().clone(), signer_priv_key.e().clone()).unwrap();

        // Stage 2: Blind Signing
        // ----------------------

        // Hash the contents of the message, getting the digest
        let (digest, iv) = hash_message::<Sha512, _, _>(&mut rng, &signer_pub_key, message)?;

        // Get the blinded digest and the unblinder
        let (blinded_digest, unblinder) = blind(&mut rng, &signer_pub_key, &digest);

        // Send the blinded-digest to the signer and get their signature
        let blind_signature = sign(&mut rng, &signer_priv_key, &blinded_digest)?;

        // Assert the the blind signature does not validate
        assert!(verify(&signer_pub_key, &digest, &blind_signature).is_err());

        // Unblind the signature
        let signature = unblind(&signer_pub_key, &blind_signature, &unblinder);

        // Stage 3: Verifiction
        // --------------------

        // Rehash the message using the iv
        let check_digest = hash_message_with_iv::<Sha512, _>(iv, &signer_pub_key, message);

        // Check that the signature matches
        verify(&signer_pub_key, &check_digest, &signature)?;

        Ok(())
    }

    #[test]
    fn manual_hash_test() -> Result<(), Error> {
        // Don't do this in real life, homomorphic versions of the message will be valid.
        let mut rng = rand::thread_rng();
        let priv_key = RSAPrivateKey::new(&mut rng, 256).unwrap();

        let mut hasher = FullDomainHash::<Sha512>::new(256 / 8).unwrap();
        hasher.input(b"ATTACKATDAWN");
        let iv: u32 = rng.gen();
        let (digest, iv) = hasher.results_under(iv, priv_key.n()).unwrap();

        let (blinded_digest, unblinder) = blind(&mut rng, &priv_key, &digest);

        let blind_signature = sign(&mut rng, &priv_key, &blinded_digest)?;

        verify(&priv_key, &blinded_digest, &blind_signature)?;

        let unblinded_signature = unblind(&priv_key, &blind_signature, &unblinder);

        verify(&priv_key, &digest, &unblinded_signature)?;

        // Reshash the message to verify it
        let mut hasher = FullDomainHash::<Sha512>::with_iv(256 / 8, iv);
        hasher.input(b"ATTACKATDAWN");

        Ok(())
    }

}
