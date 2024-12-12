# Shamir's Secret Sharing

This Rust library implements Shamir's Secret Sharing scheme, a cryptographic algorithm that allows you to split a secret into multiple shares, 
where a specified minimum number of shares are required to reconstruct the original secret. 

It is based on the original paper "How to Share a Secret" by Adi Shamir (Communications of the ACM, 1979).

## What it does

- Split a secret into `n` shares, where any `k` shares are sufficient to reconstruct the secret
- Secure against up to `k-1` compromised shares, as they reveal no information about the secret
- Supports very large secrets and primes using the `num_bigint` crate
- Includes additional extensions:
  - `BlockScheme` for handling secrets larger than the prime modulus by splitting them into smaller blocks.
  - `HierarchicalScheme` enables assigning different numbers of shares to participants based on their role or importance. 
  - `RefreshableScheme` supports generating entirely new sets of shares for the same secret, without having to redistribute the secret itself. This can be useful for regularly updating shares to maintain security.
  
Please see the documentation for more details on using these extensions.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
shamir-rs = "0.1.0"
```

Then, you can use the library like this:

```rust
use num_bigint::BigUint;
use shamir_rs::Scheme;

fn main() {
    // Choose a prime larger than the secret and total shares
    let prime = BigUint::from(257u32);
    
    // Create a new scheme with a minimum threshold of 3 shares to reconstruct, and 5 shares total
    let scheme = Scheme::new(3, 5, prime).unwrap();

    // The secret to be shared    
    let secret = BigUint::from(123u32);

    // Split the secret into shares    
    let shares = scheme.split_secret(&secret);

    // Reconstruct the secret from a subset of shares
    let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
    assert_eq!(reconstructed, secret);
}
```
