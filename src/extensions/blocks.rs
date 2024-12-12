use crate::{Scheme, Share, SssError};
use num_bigint::BigUint;
use num_traits::Zero;

pub struct BlockScheme {
    scheme: Scheme,
    prime_modulus: BigUint,
}

impl BlockScheme {
    pub fn new(
        threshold: usize,
        total_shares: usize,
        prime_modulus: BigUint,
    ) -> Result<Self, SssError> {
        // Calculate safe block size based on prime modulus
        Ok(BlockScheme {
            scheme: Scheme::new(threshold, total_shares, prime_modulus.clone())?,
            prime_modulus,
        })
    }

    pub fn split_secret(&self, secret: &BigUint) -> Vec<Vec<Share>> {
        // Calculate number of bits needed for each block based on prime size
        let prime_bits = self.prime_modulus.bits() as usize;
        let block_bits = prime_bits - 1; // Leave room for modulo
        let block_mask = (BigUint::from(1u32) << block_bits) - BigUint::from(1u32);

        let mut blocks = Vec::new();
        let mut remaining = secret.clone();

        while !remaining.is_zero() {
            let block = &remaining & &block_mask;
            blocks.push(self.scheme.split_secret(&block));
            remaining = remaining >> block_bits;
        }

        blocks
    }

    pub fn reconstruct_secret(&self, share_blocks: &[Vec<Share>]) -> Result<BigUint, SssError> {
        let prime_bits = self.prime_modulus.bits() as usize;
        let block_bits = prime_bits - 1;

        let mut result = BigUint::from(0u32);

        for (i, shares) in share_blocks.iter().enumerate() {
            let block = self.scheme.reconstruct_secret(shares)?;
            result += block << (i * block_bits);
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_processing() {
        // Use larger prime for testing
        let prime = BigUint::from(251u32);
        let scheme = BlockScheme::new(3, 5, prime).unwrap();

        // Use a smaller test value that will fit in our block size
        let secret = BigUint::from(123u32);

        // Split into shares
        let share_blocks = scheme.split_secret(&secret);

        // Reconstruct using first 3 shares of each block
        let min_shares: Vec<Vec<Share>> = share_blocks
            .iter()
            .map(|block| block[0..3].to_vec())
            .collect();

        let reconstructed = scheme.reconstruct_secret(&min_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_very_small_secret() {
        let prime = BigUint::from(251u32);
        let scheme = BlockScheme::new(3, 5, prime).unwrap();

        let secret = BigUint::from(5u32);
        let share_blocks = scheme.split_secret(&secret);

        let min_shares: Vec<Vec<Share>> = share_blocks
            .iter()
            .map(|block| block[0..3].to_vec())
            .collect();

        let reconstructed = scheme.reconstruct_secret(&min_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }
}
