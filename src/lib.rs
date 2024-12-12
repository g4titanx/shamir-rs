/// Implementation of Shamir's Secret Sharing scheme.
/// 
/// This scheme allows splitting a secret into n shares where any k shares can
/// reconstruct the secret, but k-1 shares reveal no information about the secret.
/// Based on Adi Shamir's paper "How to Share a Secret" (Communications of the ACM, 1979).
use num_bigint::{BigUint, RandBigInt};
use num_traits::identities::{One, Zero};
use thiserror::Error;

pub mod extensions;

/// These are errors that can occur during secret sharing operations
#[derive(Error, Debug)]
pub enum SssError {
    #[error("threshold k must be be in this range: 0 < k ≤ n")]
    InvalidThreshold,
    #[error("not enough shares to reconstruct secret (need {threshold}, got {share_count})")]
    NotEnoughShares {
        /// Required number of shares (k)
        threshold: usize,
        /// Actual number of shares provided
        share_count: usize,
    },
    
    /// Duplicate share indices found during reconstruction
    #[error("duplicate share indices found")]
    DuplicateShares,
}

/// A single share of a split secret, representing a point on the polynomial
#[derive(Clone, Debug, PartialEq)]
pub struct Share {
    /// The x-coordinate of the polynomial point (share index)
    pub index: u32,
    /// The y-coordinate of the polynomial point (share value)
    pub value: BigUint,
}

/// The main struct implementing Shamir's Secret Sharing scheme
#[derive(Debug)]
pub struct Scheme {
    /// Prime modulus defining the finite field ℤ/pℤ
    prime_modulus: BigUint,
    /// Minimum number of shares needed to reconstruct (k)
    threshold: usize,
    /// Total number of shares to generate (n)
    total_shares: usize,
}

impl Scheme {
    /// Creates a new Shamir's Secret Sharing scheme with the specified parameters.
    /// 
    /// # Arguments
    /// * `threshold` - Minimum number of shares needed to reconstruct the secret (k)
    /// * `total_shares` - Total number of shares to generate (n)
    /// * `prime_modulus` - Prime number defining the finite field. Must be larger
    ///                     than both the secret and total_shares.
    /// 
    /// # Returns
    /// * `Ok(Scheme)` - If parameters are valid
    /// * `Err(SssError::InvalidThreshold)` - If threshold is 0 or greater than total_shares
    /// 
    /// # Example
    /// ```
    /// use num_bigint::BigUint;
    /// use shamir_rs::Scheme;
    /// 
    /// let prime = BigUint::from(257u32);
    /// let scheme = Scheme::new(3, 5, prime).unwrap();
    /// ```
    pub fn new(
        threshold: usize,
        total_shares: usize,
        prime_modulus: BigUint,
    ) -> Result<Self, SssError> {
        if threshold == 0 || threshold > total_shares {
            return Err(SssError::InvalidThreshold);
        }

        Ok(Scheme {
            prime_modulus,
            threshold,
            total_shares,
        })
    }

    /// Splits a secret into n shares where k shares are required to reconstruct.
    /// 
    /// # Arguments
    /// * `secret` - The secret to split. Must be less than prime_modulus.
    /// 
    /// # Returns
    /// A vector of n shares. Each share is a point on a random polynomial of
    /// degree k-1 where the constant term is the secret.
    /// 
    /// # Example
    /// ```
    /// # use num_bigint::BigUint;
    /// # use shamir_rs::Scheme;
    /// # let prime = BigUint::from(257u32);
    /// # let scheme = Scheme::new(3, 5, prime).unwrap();
    /// let secret = BigUint::from(123u32);
    /// let shares = scheme.split_secret(&secret);
    /// assert_eq!(shares.len(), 5);
    /// ```
    pub fn split_secret(&self, secret: &BigUint) -> Vec<Share> {
        let secret = secret % &self.prime_modulus;
        let coefficients = self.create_polynomial(&secret);

        (1..=self.total_shares)
            .map(|x| Share {
                index: x as u32,
                value: self.evaluate_polynomial(&coefficients, x as u32),
            })
            .collect()
    }

    /// Reconstructs a secret from k or more shares using Lagrange interpolation.
    /// 
    /// # Arguments
    /// * `shares` - Slice of shares to use for reconstruction. Must contain at
    ///             least k shares with unique indices.
    /// 
    /// # Returns
    /// * `Ok(BigUint)` - The reconstructed secret
    /// * `Err(SssError::NotEnoughShares)` - If fewer than k shares provided
    /// * `Err(SssError::DuplicateShares)` - If shares contain duplicate indices
    /// 
    /// # Example
    /// ```
    /// # use num_bigint::BigUint;
    /// # use shamir_rs::Scheme;
    /// # let prime = BigUint::from(257u32);
    /// # let scheme = Scheme::new(3, 5, prime).unwrap();
    /// # let secret = BigUint::from(123u32);
    /// # let shares = scheme.split_secret(&secret);
    /// let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
    /// assert_eq!(reconstructed, secret);
    /// ```
    pub fn reconstruct_secret(&self, shares: &[Share]) -> Result<BigUint, SssError> {
        // Check if we have enough shares
        if shares.len() < self.threshold {
            return Err(SssError::NotEnoughShares {
                threshold: self.threshold,
                share_count: shares.len(),
            });
        }

        // Check for duplicate indices
        let mut seen_indices = std::collections::HashSet::new();
        for share in shares {
            if !seen_indices.insert(share.index) {
                return Err(SssError::DuplicateShares);
            }
        }

        // We only need threshold number of shares
        let shares = &shares[0..self.threshold];

        // Evaluate at x = 0 to get the secret
        let x = BigUint::from(0u32);
        let mut secret = BigUint::from(0u32);

        for i in 0..shares.len() {
            let basis = self.lagrange_basis(shares, i, &x);
            let term = (basis * &shares[i].value) % &self.prime_modulus;
            secret = (secret + term) % &self.prime_modulus;
        }

        Ok(secret)
    }

    /// Creates a random polynomial of degree k-1 where:
    /// - a₀ is the secret
    /// - all other coefficients are random
    /// - all arithmetic is done modulo prime_modulus
    pub(crate) fn create_polynomial(&self, secret: &BigUint) -> Vec<BigUint> {
        let mut rng = rand::thread_rng();
        let mut coefficients = Vec::with_capacity(self.threshold);

        // a₀ = secret
        coefficients.push(secret.clone());

        // Generate random coefficients a₁ through aₖ₋₁
        for _ in 1..self.threshold {
            // Generate a random number in range [0, prime_modulus)
            let coeff = rng.gen_biguint_range(&BigUint::from(0u32), &self.prime_modulus);
            coefficients.push(coeff);
        }

        coefficients
    }

    /// Evaluates polynomial at point x
    /// polynomial is represented by its coefficients [a₀, a₁, ..., aₖ₋₁]
    pub(crate) fn evaluate_polynomial(&self, coefficients: &[BigUint], x: u32) -> BigUint {
        let mut result = BigUint::from(0u32); // Start with 0
        let x_big = BigUint::from(x);
        let mut x_power = BigUint::from(1u32); // Start with 1

        for coeff in coefficients {
            let term = coeff * &x_power;
            result += term;
            x_power *= &x_big;
        }

        result % &self.prime_modulus
    }

    /// Calculates a modular multiplicative inverse using Extended Euclidean Algorithm
    fn mod_inverse(number: &BigUint, modulus: &BigUint) -> Option<BigUint> {
        let mut s = BigUint::zero();
        let mut old_s = BigUint::one();
        let mut t = BigUint::one();
        let mut old_t = BigUint::zero();
        let mut r = modulus.clone();
        let mut old_r = number.clone();

        while !r.is_zero() {
            let quotient = &old_r / &r;

            // Update r
            let temp_r = r.clone();
            r = old_r - &quotient * &r;
            old_r = temp_r;

            // Update s
            let temp_s = s.clone();
            s = if quotient.clone() * &s <= old_s {
                old_s - quotient.clone() * &s
            } else {
                modulus - ((quotient.clone() * &s - &old_s) % modulus)
            };
            old_s = temp_s;

            // Update t
            let temp_t = t.clone();
            t = if quotient.clone() * &t <= old_t {
                old_t - quotient * &t
            } else {
                modulus - ((quotient * &t - &old_t) % modulus)
            };
            old_t = temp_t;
        }

        if old_r > BigUint::one() {
            return None; // number and modulus aren't coprime
        }

        Some(old_s % modulus)
    }

    /// Calculates the Lagrange basis polynomial li(x) for each share:
    /// li(x) = ∏(j≠i) (x - xj)/(xi - xj)
    fn lagrange_basis(&self, shares: &[Share], i: usize, x: &BigUint) -> BigUint {
        let mut numerator = BigUint::from(1u32);
        let mut denominator = BigUint::from(1u32);
        let x_i = BigUint::from(shares[i].index);

        for j in 0..shares.len() {
            if i != j {
                let x_j = BigUint::from(shares[j].index);

                // Compute (x - x_j) mod p
                let term = self.mod_sub(x, &x_j);
                numerator = (numerator * term) % &self.prime_modulus;

                // Compute (x_i - x_j) mod p
                let diff = self.mod_sub(&x_i, &x_j);
                denominator = (denominator * diff) % &self.prime_modulus;
            }
        }

        // Calculate modular multiplicative inverse of denominator
        let denominator_inv = Self::mod_inverse(&denominator, &self.prime_modulus)
            .expect("shares should have unique indices");

        (numerator * denominator_inv) % &self.prime_modulus
    }

    /// Helper function: Perform modular subtraction (a - b) mod p
    fn mod_sub(&self, a: &BigUint, b: &BigUint) -> BigUint {
        if a >= b {
            (a - b) % &self.prime_modulus
        } else {
            let mut result = &self.prime_modulus - b;
            result += a;
            result % &self.prime_modulus
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_polynomial_evaluation() {
        let scheme = Scheme::new(3, 5, BigUint::from(17u32)).unwrap();

        // Test polynomial x² + 2x + 3 mod 17
        let coefficients: Vec<BigUint> = vec![3u32, 2u32, 1u32]
            .into_iter()
            .map(BigUint::from)
            .collect();

        assert_eq!(
            scheme.evaluate_polynomial(&coefficients, 1),
            BigUint::from(6u32)
        );

        assert_eq!(
            scheme.evaluate_polynomial(&coefficients, 2),
            BigUint::from(11u32)
        );
    }

    #[test]
    fn test_split_secret() {
        let scheme = Scheme::new(3, 5, BigUint::from(17u32)).unwrap();

        let shares = scheme.split_secret(&BigUint::from(10u32));

        assert_eq!(shares.len(), 5); // Should get 5 shares

        // All share values should be < 17 (prime modulus)
        for share in shares {
            assert!(share.value < BigUint::from(17u32));
        }
    }

    #[test]
    fn test_polynomial_randomness() {
        let scheme = Scheme::new(3, 5, BigUint::from(17u32)).unwrap();

        let secret = BigUint::from(10u32);
        let poly1 = scheme.create_polynomial(&secret);
        let poly2 = scheme.create_polynomial(&secret);

        // First coefficient (secret) should be the same
        assert_eq!(poly1[0], poly2[0]);

        // Other coefficients should be different (with very high probability)
        assert_ne!(poly1[1..], poly2[1..]);

        // All coefficients should be less than prime modulus
        for coeff in poly1.iter().chain(poly2.iter()) {
            assert!(coeff < &scheme.prime_modulus);
        }
    }

    #[test]
    fn test_secret_reconstruction() {
        let prime = BigUint::from(17u32);
        let scheme = Scheme::new(3, 5, prime).unwrap();

        let secret = BigUint::from(10u32);
        let shares = scheme.split_secret(&secret);

        // Try reconstructing with exactly k shares
        let result = scheme.reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(result, secret);

        // Try reconstructing with more than k shares
        let result = scheme.reconstruct_secret(&shares[0..4]).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn test_reconstruction_errors() {
        let prime = BigUint::from(17u32);
        let scheme = Scheme::new(3, 5, prime).unwrap();

        let secret = BigUint::from(10u32);
        let shares = scheme.split_secret(&secret);

        // Try with not enough shares
        assert!(matches!(
            scheme.reconstruct_secret(&shares[0..2]),
            Err(SssError::NotEnoughShares { .. })
        ));

        // Try with duplicate shares
        let mut duplicate_shares = shares[0..3].to_vec();
        duplicate_shares[1] = duplicate_shares[0].clone();
        assert!(matches!(
            scheme.reconstruct_secret(&duplicate_shares),
            Err(SssError::DuplicateShares)
        ));
    }

    #[test]
    fn test_mod_sub() {
        let prime = BigUint::from(17u32);
        let scheme = Scheme::new(3, 5, prime.clone()).unwrap();

        // Test cases for modular subtraction
        assert_eq!(
            scheme.mod_sub(&BigUint::from(10u32), &BigUint::from(3u32)),
            BigUint::from(7u32)
        ); // 10 - 3 = 7
        assert_eq!(
            scheme.mod_sub(&BigUint::from(3u32), &BigUint::from(10u32)),
            BigUint::from(10u32)
        ); // (17 - 10 + 3) mod 17 = 10
    }

    #[test]
    fn test_reconstruction_with_different_share_combinations() {
        let prime = BigUint::from(257u32); // Larger prime for better security testing
        let scheme = Scheme::new(3, 5, prime).unwrap();
        let secret = BigUint::from(123u32);
        let shares = scheme.split_secret(&secret);

        // Test ALL possible combinations of k shares
        let mut seen_secrets = HashSet::new();

        // Try every possible combination of 3 shares from the 5 shares
        let combinations = vec![
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 1, 4],
            vec![0, 2, 3],
            vec![0, 2, 4],
            vec![0, 3, 4],
            vec![1, 2, 3],
            vec![1, 2, 4],
            vec![1, 3, 4],
            vec![2, 3, 4],
        ];

        for combo in combinations {
            let share_subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();

            let reconstructed = scheme.reconstruct_secret(&share_subset).unwrap();
            seen_secrets.insert(reconstructed);
        }

        // All reconstructions should yield the same secret
        assert_eq!(seen_secrets.len(), 1);
        assert_eq!(seen_secrets.into_iter().next().unwrap(), secret);
    }

    #[test]
    fn test_insufficient_shares_reveal_nothing() {
        let prime = BigUint::from(257u32);
        let scheme = Scheme::new(3, 5, prime.clone()).unwrap();
        let secret = BigUint::from(123u32);
        let shares = scheme.split_secret(&secret);

        // Take all possible pairs of shares (k-1 shares)
        let pairs = vec![
            vec![0, 1],
            vec![0, 2],
            vec![0, 3],
            vec![0, 4],
            vec![1, 2],
            vec![1, 3],
            vec![1, 4],
            vec![2, 3],
            vec![2, 4],
            vec![3, 4],
        ];

        // For each pair, verify that all possible values in our field could be the secret
        for pair in pairs {
            let share_pair: Vec<Share> = pair.iter().map(|&i| shares[i].clone()).collect();

            // Verify we can't reconstruct with k-1 shares
            assert!(matches!(
                scheme.reconstruct_secret(&share_pair),
                Err(SssError::NotEnoughShares { .. })
            ));
        }
    }

    #[test]
    fn test_different_threshold_combinations() {
        let prime = BigUint::from(257u32);

        // Test different (k,n) combinations
        let configs = vec![
            (2, 3),  // minimal case
            (3, 5),  // our standard test case
            (5, 8),  // larger case
            (7, 10), // even larger case
        ];

        for (k, n) in configs {
            let scheme = Scheme::new(k, n, prime.clone()).unwrap();
            let secret = BigUint::from(123u32);
            let shares = scheme.split_secret(&secret);

            assert_eq!(shares.len(), n);

            // Should succeed with k shares
            let reconstructed = scheme.reconstruct_secret(&shares[0..k]).unwrap();
            assert_eq!(reconstructed, secret);

            // Should fail with k-1 shares
            assert!(matches!(
                scheme.reconstruct_secret(&shares[0..k - 1]),
                Err(SssError::NotEnoughShares { .. })
            ));
        }
    }

    #[test]
    fn test_edge_case_secrets() {
        let prime = BigUint::from(17u32);
        let scheme = Scheme::new(3, 5, prime.clone()).unwrap();

        // Test secret = 0
        let secret = BigUint::from(0u32);
        let shares = scheme.split_secret(&secret);
        let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);

        // Test secret = p-1 (largest possible)
        let secret = prime.clone() - BigUint::from(1u32);
        let shares = scheme.split_secret(&secret);
        let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);

        // Test secret > p (should work with modulo)
        let secret = prime.clone() * BigUint::from(2u32);
        let shares = scheme.split_secret(&secret);
        let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, BigUint::from(0u32)); // since secret mod p = 0
    }

    #[test]
    fn test_all_shares_reconstruction() {
        let prime = BigUint::from(17u32);
        let scheme = Scheme::new(3, 5, prime).unwrap();
        let secret = BigUint::from(10u32);
        let shares = scheme.split_secret(&secret);

        // Try reconstructing with all shares
        let result = scheme.reconstruct_secret(&shares).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn test_invalid_parameters() {
        let prime = BigUint::from(17u32);

        // Test k = 0
        assert!(matches!(
            Scheme::new(0, 5, prime.clone()),
            Err(SssError::InvalidThreshold)
        ));

        // Test k > n
        assert!(matches!(
            Scheme::new(6, 5, prime.clone()),
            Err(SssError::InvalidThreshold)
        ));

        // Test k = n (should work)
        assert!(Scheme::new(5, 5, prime.clone()).is_ok());
    }

    #[test]
    fn test_minimum_viable_scheme() {
        let prime = BigUint::from(17u32);
        // Test smallest possible scheme: k=2, n=2
        let scheme = Scheme::new(2, 2, prime).unwrap();
        let secret = BigUint::from(10u32);
        let shares = scheme.split_secret(&secret);

        assert_eq!(shares.len(), 2);
        let reconstructed = scheme.reconstruct_secret(&shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_large_numbers() {
        let prime = BigUint::parse_bytes(
            b"115792089237316195423570985008687907853269984665640564039457584007913129639747",
            10,
        )
        .unwrap();
        let scheme = Scheme::new(3, 5, prime.clone()).unwrap();

        let secret = prime.clone() - BigUint::from(1u32);
        let shares = scheme.split_secret(&secret);
        let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_share_index_range() {
        let prime = BigUint::from(17u32);
        let scheme = Scheme::new(3, 5, prime).unwrap();
        let secret = BigUint::from(10u32);
        let shares = scheme.split_secret(&secret);

        // verify share indices are 1 through n
        for (i, share) in shares.iter().enumerate() {
            assert_eq!(share.index as usize, i + 1);
        }
    }

    #[test]
    fn test_shuffled_shares() {
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();

        let prime = BigUint::from(17u32);
        let scheme = Scheme::new(3, 5, prime).unwrap();
        let secret = BigUint::from(10u32);
        let mut shares = scheme.split_secret(&secret);

        // shuffle the shares
        shares.shuffle(&mut rng);

        // Should still reconstruct correctly
        let reconstructed = scheme.reconstruct_secret(&shares[0..3]).unwrap();
        assert_eq!(reconstructed, secret);
    }
}
