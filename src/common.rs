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

/// Hash the message using a full-domain-hash, returning both the digest and the initialization vector.
pub fn hash_message<H: digest::Digest + Clone, P: PublicKey>(
  signer_public_key: &P,
  message: &[u8],
) -> Result<(Vec<u8>, u8), Error> {
  let size = signer_public_key.size();
  let mut hasher = FullDomainHash::<H>::new(size).unwrap(); // will never panic.
  hasher.input(message);

  // Append modulus n to the message before hashing
  let append = signer_public_key.n().to_bytes_be();
  hasher.input(append);

  let iv: u8 = 0;
  let zero = BigUint::from(0u8);
  let (digest, iv) = hasher
    .results_within(iv, &zero, signer_public_key.n())
    .map_err(|_| Error::ModulusTooLarge)?;

  Ok((digest, iv))
}

/// Verifies a signature after it has been unblinded.
pub fn verify_hashed<K: PublicKey>(pub_key: &K, hashed: &[u8], sig: &[u8]) -> Result<(), Error> {
  if hashed.len() != pub_key.size() {
    return Err(Error::Verification);
  }

  let m = BigUint::from_bytes_be(&hashed);
  if m >= *pub_key.n() {
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

/// Sign the given blinded digest.
pub fn sign_hashed<R: Rng>(
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

// Returns a new vector of the given length, with 0s left padded.
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
