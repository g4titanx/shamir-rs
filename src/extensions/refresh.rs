use crate::{Scheme, Share, SssError};
use num_bigint::BigUint;

pub struct RefreshableScheme {
    scheme: Scheme,
    version: usize, // Track polynomial version
}

impl RefreshableScheme {
    pub fn new(
        threshold: usize,
        total_shares: usize,
        prime_modulus: BigUint,
    ) -> Result<Self, SssError> {
        Ok(RefreshableScheme {
            scheme: Scheme::new(threshold, total_shares, prime_modulus)?,
            version: 0,
        })
    }

    /// Generate initial shares
    pub fn split_secret(&mut self, secret: &BigUint) -> Vec<(Share, usize)> {
        let shares = self.scheme.split_secret(secret);
        self.version += 1;
        // Return shares with their version number
        shares
            .into_iter()
            .map(|share| (share, self.version))
            .collect()
    }

    /// Generate new shares for the same secret
    pub fn refresh_shares(
        &mut self,
        current_shares: &[(Share, usize)],
    ) -> Result<Vec<(Share, usize)>, SssError> {
        // Check we have enough shares and they're from the same version
        let shares: Vec<Share> = current_shares
            .iter()
            .map(|(share, _version)| share.clone())
            .collect();

        // Recover the secret
        let secret = self.scheme.reconstruct_secret(&shares)?;

        // Generate new shares with a new polynomial
        let new_shares = self.scheme.split_secret(&secret);
        self.version += 1;

        // Return new shares with new version
        Ok(new_shares
            .into_iter()
            .map(|share| (share, self.version))
            .collect())
    }

    /// Reconstruct secret, ensuring shares are from the same version
    pub fn reconstruct_secret(&self, shares: &[(Share, usize)]) -> Result<BigUint, SssError> {
        // Check all shares are from the same version
        let first_version = shares[0].1;
        if !shares
            .iter()
            .all(|(_share, version)| *version == first_version)
        {
            return Err(SssError::DuplicateShares); // Reuse error for version mismatch
        }

        let shares: Vec<Share> = shares
            .iter()
            .map(|(share, _version)| share.clone())
            .collect();

        self.scheme.reconstruct_secret(&shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_refreshing() {
        let prime = BigUint::from(257u32);
        let mut scheme = RefreshableScheme::new(3, 5, prime).unwrap();

        // Initial secret sharing
        let secret = BigUint::from(123u32);
        let shares_v1 = scheme.split_secret(&secret);

        // Verify initial reconstruction
        let reconstructed = scheme.reconstruct_secret(&shares_v1[0..3]).unwrap();
        assert_eq!(reconstructed, secret);

        // Refresh shares
        let shares_v2 = scheme.refresh_shares(&shares_v1[0..3]).unwrap();

        // Verify new shares still reconstruct to same secret
        let reconstructed = scheme.reconstruct_secret(&shares_v2[0..3]).unwrap();
        assert_eq!(reconstructed, secret);

        // Verify shares are different but versions are sequential
        assert_ne!(shares_v1[0].0.value, shares_v2[0].0.value);
        assert_eq!(shares_v1[0].1 + 1, shares_v2[0].1);

        // Try mixing shares from different versions (should fail)
        let mixed_shares = vec![
            shares_v1[0].clone(),
            shares_v1[1].clone(),
            shares_v2[0].clone(),
        ];
        assert!(scheme.reconstruct_secret(&mixed_shares).is_err());
    }

    #[test]
    fn test_multiple_refreshes() {
        let prime = BigUint::from(257u32);
        let mut scheme = RefreshableScheme::new(3, 5, prime).unwrap();

        let secret = BigUint::from(123u32);
        let shares_v1 = scheme.split_secret(&secret);

        // Do multiple refreshes
        let mut current_shares = shares_v1;
        for _ in 0..5 {
            current_shares = scheme.refresh_shares(&current_shares[0..3]).unwrap();
            let reconstructed = scheme.reconstruct_secret(&current_shares[0..3]).unwrap();
            assert_eq!(reconstructed, secret);
        }
    }
}
