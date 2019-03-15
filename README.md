
RSA-FDH
=======

Implements an RSA-FDH signature scheme that supports blind signing.

Example
-------

```rust
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
let (digest, iv) = hash_message::<Sha512, _, _>(message, &signer_pub_key, &mut rng)?;

// Get the blinded digest and the unblinder
let (blinded_digest, unblinder) = blind(&signer_pub_key, &mut rng, &digest);

// Send the blinded-digest to the signer and get their signature
let blind_signature = sign(Some(&mut rng), &signer_priv_key, &blinded_digest)?;

// Unblind the signature
let signature = unblind(&signer_pub_key, &blind_signature, &unblinder);

// Stage 3: Verifiction
// --------------------

// Rehash the message using the iv
let check_digest = hash_message_with_iv::<Sha512, _>(message, &signer_pub_key, iv);

// Check that the signature matches
verify(&signer_pub_key, &check_digest, &signature)?;
```