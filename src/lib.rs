use failure::Fail;
use num_bigint_dig::BigUint;
use rand::Rng;
use rsa::errors::Error as RSAError;
use rsa::internals;
use rsa::{PublicKey, RSAPrivateKey};
use subtle::ConstantTimeEq;

/// Error types
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "rsa-fdh: digest numeric value is too large")]
    DigestTooLarge,
    #[fail(display = "rsa-fdh: digest is incorrectly sized")]
    DigestIncorrectSize,
    #[fail(display = "rsa-fdh: verification failed")]
    Verification,
    #[fail(display = "rsa-fdh: rsa error: {}", 0)]
    RSAError(RSAError),
}

pub fn sign<R: Rng>(
    rng: Option<&mut R>,
    priv_key: &RSAPrivateKey,
    hashed: &[u8],
) -> Result<Vec<u8>, Error> {
    // TODO: Check message size and refuse to sign if too small.

    if priv_key.size() < hashed.len() {
        return Err(Error::DigestIncorrectSize);
    }

    let n = priv_key.n();
    let m = BigUint::from_bytes_be(&hashed);

    if m >= *n {
        return Err(Error::DigestTooLarge);
    }

    let c = internals::decrypt_and_check(rng, priv_key, &m)
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
pub fn blind<R: Rng>(priv_key: &RSAPrivateKey, rng: &mut R, digest: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let c = BigUint::from_bytes_be(digest);
    let (c, unblinder) = internals::blind::<R>(rng, priv_key, &c);
    (c.to_bytes_be(), unblinder.to_bytes_be())
}

/// Unblind the given signature, producing a signature that also signs the unblided digest.
pub fn unblind(priv_key: &RSAPrivateKey, blinded_sig: &[u8], unblinder: &[u8]) -> Vec<u8> {
    let blinded_sig = BigUint::from_bytes_be(blinded_sig);
    let unblinder = BigUint::from_bytes_be(unblinder);
    let unblinded = internals::unblind(priv_key, &blinded_sig, &unblinder);
    unblinded.to_bytes_be()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use fdh::{FullDomainHash, Input, VariableOutput};
    use rsa::{PublicKey, RSAPrivateKey};
    use sha2::Sha512;

    #[test]
    fn basic_test() -> Result<(), Error> {
        let mut rng = rand::thread_rng();
        let priv_key = RSAPrivateKey::new(&mut rng, 256).unwrap();
        let mut hasher = FullDomainHash::<Sha512>::new(256 / 8).unwrap();
        hasher.input(b"ATTACKATDAWN");
        let iv: u32 = rng.gen();
        let (digest, iv) = hasher.results_under(iv, priv_key.n()).unwrap();

        let (blinded_digest, unblinder) = blind(&priv_key, &mut rng, &digest);

        let blind_signature = sign(Some(&mut rng), &priv_key, &blinded_digest)?;

        verify(&priv_key, &blinded_digest, &blind_signature)?;

        let unblinded_signature = unblind(&priv_key, &blind_signature, &unblinder);

        verify(&priv_key, &digest, &unblinded_signature)?;

        // Reshash the message to verify it
        let mut hasher = FullDomainHash::<Sha512>::with_iv(256 / 8, iv).unwrap();
        hasher.input(b"ATTACKATDAWN");

        Ok(())
    }
}
