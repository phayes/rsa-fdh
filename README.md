
RSA-FDH
=======

Implements an RSA-FDH signature scheme that supports blind signing.

### Caveats

1. The signing key should only be used as part of RSA-FHD. Key re-use for encryption or as part of other protocols can result in key disclosure. 

2. This module and it's dependencies have not undergone a security audit. The 1.0 version will not be released until it does.

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

// Hash the contents of the message, getting the digest and the initialization vector
let (digest, iv) = rsa_fdh::hash_message::<Sha256, _, _>(&mut rng, &signer_pub_key, message)?;

// Get the blinded digest and the secret unblinder
let (blinded_digest, unblinder) = rsa_fdh::blind(&mut rng, &signer_pub_key, &digest);

// Send the blinded-digest to the signer and get their signature
let blind_signature = rsa_fdh::sign(&mut rng, &signer_priv_key, &blinded_digest)?;

// Unblind the signature using the secret unblinder
let signature = rsa_fdh::unblind(&signer_pub_key, &blind_signature, &unblinder);


// Stage 3: Verification
// ---------------------

// Rehash the message using the initialization vector
let check_digest = rsa_fdh::hash_message_with_iv::<Sha256, _>(iv, &signer_pub_key, message);

// Verify the signature
rsa_fdh::verify(&signer_pub_key, &check_digest, &signature)?;
```


Protocol Description
--------------------

A full domain hash (FDH) is constructed as follows:

`FDH(𝑀, 𝐼𝑉) = H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 0) ‖ H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 1) ‖ H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 2) ... = 𝐃`

Where:
 - `𝐃` is the resulting digest
 - `𝑀` is the message
 - `H` is any hash function
 - `𝑁` is the signing key's public modulus
 - `𝐼𝑉` is a one-byte initialization vector

The message is hashed (along with `𝑁` and `𝐼𝑉 + incrementing suffix`) in rounds until the length of the hash is equal to the length of `𝑁`. The hash is truncated as needed.

Because `𝐃` must be also smaller than `𝑁`, we interate on different `𝐼𝑉`s until we find a `𝐃` that is smaller than `𝑁`. Pseudocode:

```
iv = random_iv()
digest = fdh(m, iv)
while digest.as_int() > modulus_n:
  iv++
  digest = fdh(m, iv)
return (digest, iv)
```

Blinding, unblinding, signing and verification are then all done in the usual way for RSA, using the digest `D` as the message with no additional padding.