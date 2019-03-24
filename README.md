
RSA-FDH
-------

[![Build Status](https://travis-ci.org/phayes/rsa-fdh.svg?branch=master)](https://travis-ci.org/phayes/rsa-fdh)
[![codecov](https://codecov.io/gh/phayes/rsa-fdh/branch/master/graph/badge.svg)](https://codecov.io/gh/phayes/rsa-fdh)

RSA-FDH is a is provably secure blind-signing signature scheme that uses RSA and a [full domain hash](https://github.com/phayes/fdh-rs).

This project implements two RSA-FDH signature schemes:

1. A regular signature scheme with Full Domain Hash (FDH) padding.

2. A blind signature scheme that that supports blind-signing to keep the message being signed secret from the signer.

### Caveats

1. When using the blind signature scheme, the signing key should only be used as part of RSA-FDH blind-signing. Key re-use for encryption or as part of other protocols can result in key disclosure. 

2. This project and it's dependencies have not undergone a security audit. The 1.0 version will not be released until it does. If you are interested in performing a security audit, please see [this ticket](https://github.com/phayes/rsa-fdh/issues/1).

Regular signature scheme example
--------------------------------

```rust
use rsa_fdh;
use rsa::{RSAPrivateKey, RSAPublicKey};
use sha2::{Sha256, Digest};

// Set up rng and message
let mut rng = rand::thread_rng();
let message = b"NEVER GOING TO GIVE YOU UP";

// Create the keys
let signer_priv_key = RSAPrivateKey::new(&mut rng, 256)?;
let signer_pub_key: RSAPublicKey = signer_priv_key.clone().into();

// Apply a standard digest to the message
let mut hasher = Sha256::new();
hasher.input(message);
let digest = hasher.result();

// Obtain a signture
let signature = rsa_fdh::sign::<Sha256, _>(&mut rng, &signer_priv_key, &digest)?;

// Verify the signature
rsa_fdh::verify::<Sha256, _>(&signer_pub_key, &digest, &signature)?;

```


Blind signature scheme example
------------------------------

```rust
use rsa_fdh;
use rsa::{RSAPrivateKey, RSAPublicKey};
use sha2::{Sha256, Digest};

// Set up rng and message
let mut rng = rand::thread_rng();
let message = b"NEVER GOING TO GIVE YOU UP";

// Create the keys
let signer_priv_key = RSAPrivateKey::new(&mut rng, 256)?;
let signer_pub_key: RSAPublicKey = signer_priv_key.clone().into();

// Hash the contents of the message with a Full Domain Hash, getting the digest
let digest = blind::hash_message::<Sha256, _>(&signer_pub_key, message)?;

// Get the blinded digest and the secret unblinder
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
 - 𝑀 is the message
 - H is any hash function
 - 𝑁 is the signing key's public modulus
 - 𝐼𝑉 is a one-byte initialization vector

The message is hashed (along with 𝑁 and 𝐼𝑉 + incrementing suffix) in rounds until the length of the hash is greater than or equal to the length of 𝑁. The hash is truncated as needed to produce the digest 𝐷 with the same length as 𝑁.

𝐷 must also be smaller than 𝑁, so we increment 𝐼𝑉 until we find a 𝐷 that is smaller than 𝑁. 

Pseudocode:
```
fn generate_digest(message, public_key):
    fdh = create_fdh(algo=sha256, length=public_key.bitlen())
    iv = 0
    digest = fdh(message, iv)
    while digest.as_int() > public_key.n():
        iv++
        digest = fdh(message, iv)
    return digest
```

The `while` loop finishes within a minimal number of iterations because 𝑁 generally occurs around `(2^bitlen) / 2`.

Two signature schemes are supported:

1. In the regular signature scheme, the signer applies the FDH before signing the message. 

2. In the blind-signature scheme, the sender applies the FDH to the message before blinding the resulting digest and sending it to the signer, who signs the blinded digest directly. The signer must not re-use their private keys for encryption outside of the RSA-FDH blind-signature protocol. 

Blinding, unblinding, signing and verification are done in the usual way for RSA.
