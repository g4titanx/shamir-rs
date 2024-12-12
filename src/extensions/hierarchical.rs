use crate::{Scheme, Share, SssError};
use num_bigint::BigUint;

#[derive(Debug, Clone)]
pub enum Role {
    President,     // Gets 3 shares
    VicePresident, // Gets 2 shares
    Executive,     // Gets 1 share
}

#[derive(Debug)]
pub struct HierarchicalShare {
    pub role: Role,
    pub shares: Vec<Share>,
}

pub struct HierarchicalScheme {
    scheme: Scheme,
}

impl HierarchicalScheme {
    pub fn new(prime_modulus: BigUint) -> Result<Self, SssError> {
        // We use (3,n) scheme as base, where n will be determined by total shares
        Ok(HierarchicalScheme {
            scheme: Scheme::new(3, 100, prime_modulus)?, // n=100 as safe upper bound
        })
    }

    pub fn split_secret(&self, secret: &BigUint) -> Vec<Share> {
        self.scheme.split_secret(secret)
    }

    pub fn assign_shares(&self, all_shares: Vec<Share>, role: Role) -> HierarchicalShare {
        let num_shares = match role {
            Role::President => 3,
            Role::VicePresident => 2,
            Role::Executive => 1,
        };

        // Take sequential shares for this role
        let role_shares: Vec<Share> = all_shares.into_iter().take(num_shares).collect();

        HierarchicalShare {
            role,
            shares: role_shares,
        }
    }

    pub fn reconstruct_secret(&self, shares: &[Share]) -> Result<BigUint, SssError> {
        self.scheme.reconstruct_secret(shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_president_alone() {
        let scheme = HierarchicalScheme::new(BigUint::from(257u32)).unwrap();
        let secret = BigUint::from(123u32);
        let all_shares = scheme.split_secret(&secret);

        // President gets 3 shares
        let president = scheme.assign_shares(all_shares, Role::President);

        // President should be able to reconstruct alone
        let reconstructed = scheme.reconstruct_secret(&president.shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_two_vice_presidents() {
        let scheme = HierarchicalScheme::new(BigUint::from(257u32)).unwrap();
        let secret = BigUint::from(123u32);
        let all_shares = scheme.split_secret(&secret);

        // Create shares for two VPs
        let mut shares_iter = all_shares.into_iter();
        let vp1_shares = shares_iter.by_ref().take(2).collect();
        let vp2_shares = shares_iter.by_ref().take(2).collect();

        let vp1 = HierarchicalShare {
            role: Role::VicePresident,
            shares: vp1_shares,
        };

        let vp2 = HierarchicalShare {
            role: Role::VicePresident,
            shares: vp2_shares,
        };

        // Combine some shares from both VPs to reconstruct
        let mut combined_shares = Vec::new();
        combined_shares.extend_from_slice(&vp1.shares[0..2]);
        combined_shares.push(vp2.shares[0].clone());

        let reconstructed = scheme.reconstruct_secret(&combined_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_vp_and_executives() {
        let scheme = HierarchicalScheme::new(BigUint::from(257u32)).unwrap();
        let secret = BigUint::from(123u32);
        let all_shares = scheme.split_secret(&secret);

        let mut shares_iter = all_shares.into_iter();

        // VP gets 2 shares
        let vp_shares = shares_iter.by_ref().take(2).collect();
        let vp = HierarchicalShare {
            role: Role::VicePresident,
            shares: vp_shares,
        };

        // Exec gets 1 share
        let exec_shares = shares_iter.by_ref().take(1).collect();
        let exec = HierarchicalShare {
            role: Role::Executive,
            shares: exec_shares,
        };

        // VP + Exec should be able to reconstruct
        let mut combined_shares = Vec::new();
        combined_shares.extend_from_slice(&vp.shares);
        combined_shares.extend_from_slice(&exec.shares);

        let reconstructed = scheme.reconstruct_secret(&combined_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_three_executives() {
        let scheme = HierarchicalScheme::new(BigUint::from(257u32)).unwrap();
        let secret = BigUint::from(123u32);
        let all_shares = scheme.split_secret(&secret);

        let mut shares_iter = all_shares.into_iter();

        // Create three executives with one share each
        let exec1 = HierarchicalShare {
            role: Role::Executive,
            shares: shares_iter.by_ref().take(1).collect(),
        };
        let exec2 = HierarchicalShare {
            role: Role::Executive,
            shares: shares_iter.by_ref().take(1).collect(),
        };
        let exec3 = HierarchicalShare {
            role: Role::Executive,
            shares: shares_iter.by_ref().take(1).collect(),
        };

        // Three executives together should be able to reconstruct
        let mut combined_shares = Vec::new();
        combined_shares.extend_from_slice(&exec1.shares);
        combined_shares.extend_from_slice(&exec2.shares);
        combined_shares.extend_from_slice(&exec3.shares);

        let reconstructed = scheme.reconstruct_secret(&combined_shares).unwrap();
        assert_eq!(reconstructed, secret);
    }
}
