
RSA-FDH
=======

Rust implementation of an RSA-FDH signature scheme that supports blind signatures.

RSA-FDH is a is provably secure blind-signing signature scheme that uses RSA and a full domain hash.

### Caveats

1. The signing key should only be used as part of RSA-FHD. Key re-use for encryption or as part of other protocols can result in key disclosure. 

2. This module and it's dependencies have not undergone a security audit. The 1.0 version will not be released until it does.

Example without blind-singing
-----------------------------

```rust
use rsa_fdh;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};
use sha2::Sha256;

// Set up rng and message
let mut rng = rand::thread_rng();
let message = b"NEVER GOING TO GIVE YOU UP";

// Create the keys
let signer_priv_key = RSAPrivateKey::new(&mut rng, 256)?;
let signer_pub_key = RSAPublicKey::new(
  signer_priv_key.n().clone(), 
  signer_priv_key.e().clone()
)?;

// Apply a standard digest to the message
let mut hasher = Sha256::new();
hasher.input(message);
let digest = hasher.result();

// Obtain a signture
let signature = rsa_fdh::sign::<Sha256, _>(&mut rng, &signer_priv_key, &digest)?;

// Verify the signature
rsa_fdh::verify::<Sha256, _>(&signer_pub_key, &digest, &signature)?;

```


Example with blind-singing
---------------------

```rust
use rsa_fdh::blind;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey};
use sha2::Sha256;

// Set up rng and message
let mut rng = rand::thread_rng();
let message = b"NEVER GOING TO GIVE YOU UP";

// Create the keys
let signer_priv_key = RSAPrivateKey::new(&mut rng, 256)?;
let signer_pub_key = RSAPublicKey::new(
  signer_priv_key.n().clone(), 
  signer_priv_key.e().clone()
)?;

// Hash the contents of the message with a Full Domain Hash, getting the digest
let digest = blind::hash_message::<Sha256, _>(&signer_pub_key, message)?;

// Get the blinded digest and the unblinder
let (blinded_digest, unblinder) = blind::blind(&mut rng, &signer_pub_key, &digest);

// Send the blinded-digest to the signer and get their signature
let blind_signature = blind::sign(&mut rng, &signer_priv_key, &blinded_digest)?;

// Unblind the signature
let signature = blind::unblind(&signer_pub_key, &blind_signature, &unblinder);

// Verify the signature
blind::verify(&signer_pub_key, &digest, &signature)?;
```


Protocol Description
--------------------

A full domain hash (FDH) is constructed as follows:

`FDH(𝑀, 𝐼𝑉) = H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 0) ‖ H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 1) ‖ H(𝑀 ‖ 𝑁 ‖ 𝐼𝑉 + 2) ...`

Where:
 - `𝑀` is the message
 - `H` is any hash function
 - `𝑁` is the signing key's public modulus
 - `𝐼𝑉` is a one-byte initialization vector

The message is hashed (along with `𝑁` and `𝐼𝑉 + incrementing suffix`) in rounds until the length of the hash is greater than or equal to the length of `𝑁`. The hash is truncated as needed to produce the digest `𝐷` with the same length as `𝑁`.

`𝐷` must also be smaller than `𝑁`, so we increment `𝐼𝑉`s until we find a `𝐷` that is smaller than `𝑁`. 

Pseudocode:
```
message = "hunter2"
modulus_n = public_key.n()
fdh = create_fdh(sha256, modulus_n.bitlen())
iv = 0
digest = fdh(message, iv)
while digest.as_int() > modulus_n:
  iv++
  digest = fdh(message, iv)
return (digest, iv)
```

In the regular signature scheme, the signer applies the FDH before signing the message. 

In the blind-signature scheme, the sender applies the FDH to the message before blinding the resulting digest and sending it to the signer, who signs the blinded digest directly. The signer must not re-use their private keys for encryption outside of the RSA-FDH blind-signature protocol. 

Blinding, unblinding, signing and verification are then all done in the usual way for RSA.
