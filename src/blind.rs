pub use crate::common::sign_hashed as sign;
pub use crate::common::verify_hashed as verify;
use num_bigint_dig::BigUint;
use rand::Rng;
use rsa::internals;
use rsa::PublicKey;

/// Hash the message as a Full Domain Hash
pub fn hash_message<H: digest::Digest + Clone, P: PublicKey>(
  signer_public_key: &P,
  message: &[u8],
) -> Result<Vec<u8>, crate::Error> {
  let (result, _iv) = crate::common::hash_message::<H, P>(signer_public_key, message)?;
  Ok(result)
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

#[cfg(test)]
mod tests {
  use crate::blind;
  use crate::Error;
  use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};
  use sha2::Sha256;

  #[test]
  fn blind_test() -> Result<(), Error> {
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
      let digest = blind::hash_message::<Sha256, _>(&signer_pub_key, message)?;

      // Get the blinded digest and the unblinder
      let (blinded_digest, unblinder) = blind::blind(&mut rng, &signer_pub_key, &digest);

      // Send the blinded-digest to the signer and get their signature
      let blind_signature = blind::sign(&mut rng, &signer_priv_key, &blinded_digest)?;

      // Assert the the blind signature does not validate against the orignal digest.
      assert!(blind::verify(&signer_pub_key, &digest, &blind_signature).is_err());

      // Unblind the signature
      let signature = blind::unblind(&signer_pub_key, &blind_signature, &unblinder);

      // Stage 3: Verification
      // ---------------------

      // Rehash the message using the iv
      let check_digest = blind::hash_message::<Sha256, _>(&signer_pub_key, message)?;

      // Check that the signature matches on the unblinded signature and the rehashed digest.
      blind::verify(&signer_pub_key, &check_digest, &signature)?;
    }

    Ok(())
  }

}
