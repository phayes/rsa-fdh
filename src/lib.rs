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

/// Blind sign the given blinded digest.
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
        .map_err(Error::RSAError)?
        .to_bytes_be();

    Ok(c)
}

/// Verifies a signature after it has been unblinded.
pub fn verify<K: PublicKey>(pub_key: &K, hashed: &[u8], sig: &[u8]) -> Result<(), Error> {
    if hashed.len() != pub_key.size() {
        return Err(Error::Verification);
    }

    let n = pub_key.n();
    let m = BigUint::from_bytes_be(&hashed);
    if m >= *n {
        return Err(Error::Verification);
    }

    let c = BigUint::from_bytes_be(sig);
    let mut m = internals::encrypt(pub_key, &c).to_bytes_be();
    if m.len() < hashed.len() {
        m = left_pad(&m, hashed.len());
    }

    // Constant time compare message with hashed
    let ok = m.ct_eq(&hashed);

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

/// Hash the message using a full-domain-hash, returning both the digest and the initialization vector.
pub fn hash_message<H: digest::Digest + Clone, R: Rng, P: PublicKey>(
    rng: &mut R,
    signer_public_key: &P,
    message: &[u8],
) -> Result<(Vec<u8>, u8), Error> {
    let size = signer_public_key.size();
    let mut hasher = FullDomainHash::<H>::new(size).unwrap(); // will never panic.
    hasher.input(message);

    // Append modulus n to the message before hashing
    let append = signer_public_key.n().to_bytes_be();
    hasher.input(append);

    let iv: u8 = rng.gen();
    let zero = BigUint::from(0u8);
    let (digest, iv) = hasher
        .results_within(iv, &zero, signer_public_key.n())
        .map_err(|_| Error::ModulusTooLarge)?;

    Ok((digest, iv))
}

/// Hash the message using a full-domain-hash with the provided initialization vector, returning the digest.
pub fn hash_message_with_iv<H: digest::Digest + Clone, P: PublicKey>(
    iv: u8,
    signer_public_key: &P,
    message: &[u8],
) -> Vec<u8> {
    let size = signer_public_key.size();
    let mut hasher = FullDomainHash::<H>::with_iv(size, iv);
    hasher.input(message);

    // Append modulus n to the message before hashing
    let append = signer_public_key.n().to_bytes_be();
    hasher.input(append);

    hasher.vec_result()
}

/// Returns a new vector of the given length, with 0s left padded.
pub fn left_pad(input: &[u8], size: usize) -> Vec<u8> {
    let n = if input.len() > size {
        size
    } else {
        input.len()
    };

    let mut out = vec![0u8; size];
    out[size - n..].copy_from_slice(input);
    out
}

#[cfg(test)]
mod tests {
    use crate::*;
    use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};
    use sha2::Sha256;

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

        // Do this a bunch so that we get a good sampling of possibe digests.
        for _ in 0..500 {
            // Stage 2: Blind Signing
            // ----------------------

            // Hash the contents of the message, getting the digest
            let (digest, iv) = hash_message::<Sha256, _, _>(&mut rng, &signer_pub_key, message)?;

            // Get the blinded digest and the unblinder
            let (blinded_digest, unblinder) = blind(&mut rng, &signer_pub_key, &digest);

            // Send the blinded-digest to the signer and get their signature
            let blind_signature = sign(&mut rng, &signer_priv_key, &blinded_digest)?;

            // Assert the the blind signature does not validate against the orignal digest.
            assert!(verify(&signer_pub_key, &digest, &blind_signature).is_err());

            // Unblind the signature
            let signature = unblind(&signer_pub_key, &blind_signature, &unblinder);

            // Stage 3: Verification
            // ---------------------

            // Rehash the message using the iv
            let check_digest = hash_message_with_iv::<Sha256, _>(iv, &signer_pub_key, message);

            // Check that the signature matches on the unblinded signature and the rehashed digest.
            verify(&signer_pub_key, &check_digest, &signature)?;
        }

        Ok(())
    }

}
