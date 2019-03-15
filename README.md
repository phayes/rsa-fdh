
RSA-FDH
=======

Implements an RSA-FDH signature scheme that supports blind signing.

### Caveats

1. The signatures are homomorphic, so each signing key should only be used as part of RSA-FHD. Key re-use for encryption or as part of other protocols can result in key disclosure. 

2. This module and it's dependencies have not undergone a security audit. The 1.0 version will not e released until it does.

Example
-------

```rust
use rsa_fdh;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};
use sha2::Sha256;

// Stage 1: Setup
// --------------
let mut rng = rand::thread_rng();
let message = b"NEVER GOING TO GIVE YOU UP";

// Create the keys
let signer_priv_key = RSAPrivateKey::new(&mut rng, 256)?;
let signer_pub_key = RSAPublicKey::new(
  signer_priv_key.n().clone(), 
  signer_priv_key.e().clone()
)?;

// Stage 2: Blind Signing
// ----------------------

// Hash the contents of the message, getting the digest
let (digest, iv) = hash_message::<Sha256, _, _>(&mut rng, &signer_pub_key, message)?;

// Get the blinded digest and the unblinder
let (blinded_digest, unblinder) = blind(&mut rng, &signer_pub_key, &digest);

// Send the blinded-digest to the signer and get their signature
let blind_signature = sign(&mut rng, &signer_priv_key, &blinded_digest)?;

// Unblind the signature
let signature = unblind(&signer_pub_key, &blind_signature, &unblinder);

// Stage 3: Verifiction
// --------------------

// Rehash the message using the iv
let check_digest = hash_message_with_iv::<Sha256, _>(iv, &signer_pub_key, message);

// Check that the signature matches
verify(&signer_pub_key, &check_digest, &signature)?;
```