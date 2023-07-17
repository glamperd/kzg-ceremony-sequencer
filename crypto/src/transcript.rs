use super::{CeremonyError, Contribution, Powers, G1, G2};
use crate::{engine::Engine, signature::BlsSignature};
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Transcript {
    #[serde(flatten)]
    pub powers: Powers,

    pub witness: Witness,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Witness {
    #[serde(rename = "runningProducts")]
    pub products: Vec<G1>,

    #[serde(rename = "potPubkeys")]
    pub pubkeys: Vec<G2>,

    #[serde(rename = "blsSignatures")]
    pub signatures: Vec<BlsSignature>,
}

impl Transcript {
    /// Create a new transcript for a ceremony of a given size.
    ///
    /// # Panics
    ///
    /// There must be at least two g1 and two g2 points, and there must be at
    /// least as many g1 as g2 points.
    #[must_use]
    pub fn new(num_g1: usize, num_g2: usize) -> Self {
        assert!(num_g1 >= 2);
        assert!(num_g2 >= 2);
        assert!(num_g1 >= num_g2);
        Self {
            powers: Powers::new(num_g1, num_g2),
            witness: Witness {
                products: vec![G1::one()],
                pubkeys: vec![G2::one()],
                signatures: vec![BlsSignature::empty()],
            },
        }
    }

    /// Returns the number of participants that contributed to this transcript.
    #[must_use]
    pub fn num_participants(&self) -> usize {
        self.witness.pubkeys.len() - 1
    }

    /// True if there is at least one contribution.
    #[must_use]
    pub fn has_entropy(&self) -> bool {
        self.num_participants() > 0
    }

    /// Creates the start of a new contribution.
    #[must_use]
    pub fn contribution(&self) -> Contribution {
        Contribution {
            powers: self.powers.clone(),
            pot_pubkey: G2::one(),
            bls_signature: BlsSignature::empty(),
        }
    }

    /// Verifies a contribution.
    #[instrument(level = "info", skip_all, fields(n1=self.powers.g1.len(), n2=self.powers.g2.len()))]
    pub fn verify<E: Engine>(&self, contribution: &Contribution) -> Result<(), CeremonyError> {
        // Compatibility checks
        if self.powers.g1.len() != contribution.powers.g1.len() {
            return Err(CeremonyError::UnexpectedNumG1Powers(
                self.powers.g1.len(),
                contribution.powers.g1.len(),
            ));
        }
        if self.powers.g2.len() != contribution.powers.g2.len() {
            return Err(CeremonyError::UnexpectedNumG2Powers(
                self.powers.g2.len(),
                contribution.powers.g2.len(),
            ));
        }

        // Verify the contribution points (encoding and subgroup checks).
        E::validate_g1(&contribution.powers.g1)?;
        E::validate_g2(&contribution.powers.g2)?;
        E::validate_g2(&[contribution.pot_pubkey])?;

        // Non-zero check
        if contribution.pot_pubkey == G2::zero() {
            return Err(CeremonyError::ZeroPubkey);
        }

        // Verify pairings.
        E::verify_pubkey(
            contribution.powers.g1[1],
            self.powers.g1[1],
            contribution.pot_pubkey,
        )?;
        E::verify_g1(&contribution.powers.g1, contribution.powers.g2[1])?;
        E::verify_g2(
            &contribution.powers.g1[..contribution.powers.g2.len()],
            &contribution.powers.g2,
        )?;

        // Accept
        Ok(())
    }

    /// Verifies a historical contribution.
    pub fn verify_inclusion<E: Engine>(&self, start: usize) -> Result<(), CeremonyError> {
        assert!(start < self.witness.products.len());

        // Find contribution in witness

        // Loop through subsequent witness entries. Do pairing check on each.
        let mut index = start;

        while index < self.witness.products.len() {
            // Pairing check: this pubkey, this & prev products
            E::verify_pubkey(
                self.witness.products[index],
                self.witness.products[index - 1],
                self.witness.pubkeys[index],
            )?;

            index += 1;
        }

        Ok(())
    }

    /// Adds a contribution to the transcript. The contribution must be
    /// verified.
    pub fn add(&mut self, contribution: Contribution) {
        self.witness.products.push(contribution.powers.g1[1]);
        self.witness.pubkeys.push(contribution.pot_pubkey);
        self.witness.signatures.push(contribution.bls_signature);
        self.powers = contribution.powers;
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        CeremonyError::{
            G1PairingFailed, G2PairingFailed, InvalidG1Power, InvalidG2Power, PubKeyPairingFailed,
            UnexpectedNumG1Powers, UnexpectedNumG2Powers,
        },
        DefaultEngine,
        ParseError::InvalidSubgroup,
    };
    use ark_bls12_381::{Fr, G1Affine, G2Affine};
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use hex_literal::hex;

    #[test]
    fn transcript_json() {
        let t = Transcript::new(4, 2);
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
            "numG1Powers": 4,
            "numG2Powers": 2,
            "powersOfTau": {
                "G1Powers": [
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
                ],
                "G2Powers": [
                "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                ],
            },
            "witness": {
                "runningProducts": [
                    "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
                ],
                "potPubkeys": [
                    "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
                ],
                "blsSignatures": [""],
            }
            })
        );
        let deser = serde_json::from_value::<Transcript>(json).unwrap();
        assert_eq!(deser, t);
    }

    #[test]
    fn test_verify_g1_not_in_subgroup() {
        let transcript = Transcript::new(2, 2);
        let point_not_in_g1 = G1(hex!("800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        let bad_g1_contribution = Contribution {
            powers: Powers {
                g1: vec![point_not_in_g1, point_not_in_g1],
                g2: vec![G2::zero(), G2::zero()],
            },
            pot_pubkey: G2::zero(),
            bls_signature: BlsSignature::empty(),
        };
        let result = transcript
            .verify::<DefaultEngine>(&bad_g1_contribution)
            .err()
            .unwrap();
        assert!(matches!(result, InvalidG1Power(_, InvalidSubgroup)));
    }

    #[test]
    fn test_verify_g2_not_in_subgroup() {
        let transcript = Transcript::new(2, 2);
        let point_not_in_g2 = G2(hex!("a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"));

        let bad_g2_contribution = Contribution {
            powers: Powers {
                g1: vec![G1::zero(), G1::zero()],
                g2: vec![point_not_in_g2, point_not_in_g2],
            },
            pot_pubkey: G2::zero(),
            bls_signature: BlsSignature::empty(),
        };
        let result = transcript
            .verify::<DefaultEngine>(&bad_g2_contribution)
            .err()
            .unwrap();
        assert!(matches!(result, InvalidG2Power(_, InvalidSubgroup)));
    }

    #[test]
    fn test_verify_wrong_pubkey() {
        let transcript = Transcript::new(2, 2);

        let secret = Fr::from(42);
        let bad_secret = Fr::from(43);
        let g1_gen = G1::from(G1Affine::prime_subgroup_generator());
        let g1_elem = G1::from(
            G1Affine::prime_subgroup_generator()
                .mul(secret)
                .into_affine(),
        );
        let g2_gen = G2::from(G2Affine::prime_subgroup_generator());
        let g2_elem = G2::from(
            G2Affine::prime_subgroup_generator()
                .mul(secret)
                .into_affine(),
        );
        let pubkey = G2::from(
            G2Affine::prime_subgroup_generator()
                .mul(bad_secret)
                .into_affine(),
        );
        let bad_pot_pubkey = Contribution {
            powers: Powers {
                g1: vec![g1_gen, g1_elem],
                g2: vec![g2_gen, g2_elem],
            },
            pot_pubkey: pubkey,
            bls_signature: BlsSignature::empty(),
        };
        assert_eq!(
            transcript
                .verify::<DefaultEngine>(&bad_pot_pubkey)
                .err()
                .unwrap(),
            PubKeyPairingFailed
        );
    }

    #[test]
    fn test_verify_wrong_g1_powers() {
        let transcript = Transcript::new(3, 2);
        let g1_1 = G1Affine::prime_subgroup_generator();
        let g1_2 = G1Affine::prime_subgroup_generator()
            .mul(Fr::from(2))
            .into_affine();
        let g1_3 = G1Affine::prime_subgroup_generator()
            .mul(Fr::from(3))
            .into_affine();
        let g2_1 = G2Affine::prime_subgroup_generator();
        let g2_2 = G2Affine::prime_subgroup_generator()
            .mul(Fr::from(2))
            .into_affine();
        let contribution = Contribution {
            powers: Powers {
                // Pretend Tau is 2, but make the third element g1^3 instead of g1^4.
                g1: vec![G1::from(g1_1), G1::from(g1_2), G1::from(g1_3)],
                g2: vec![G2::from(g2_1), G2::from(g2_2)],
            },
            pot_pubkey: G2::from(g2_2),
            bls_signature: BlsSignature::empty(),
        };
        assert_eq!(
            transcript
                .verify::<DefaultEngine>(&contribution)
                .err()
                .unwrap(),
            G1PairingFailed
        );
    }

    #[test]
    fn test_verify_wrong_g2_powers() {
        let transcript = Transcript::new(3, 3);
        let g1_1 = G1Affine::prime_subgroup_generator();
        let g1_2 = G1Affine::prime_subgroup_generator()
            .mul(Fr::from(2))
            .into_affine();
        let g1_4 = G1Affine::prime_subgroup_generator()
            .mul(Fr::from(4))
            .into_affine();
        let g2_1 = G2Affine::prime_subgroup_generator();
        let g2_2 = G2Affine::prime_subgroup_generator()
            .mul(Fr::from(2))
            .into_affine();
        let g2_3 = G2Affine::prime_subgroup_generator()
            .mul(Fr::from(3))
            .into_affine();
        let contribution = Contribution {
            powers: Powers {
                g1: vec![G1::from(g1_1), G1::from(g1_2), G1::from(g1_4)],
                // Pretend Tau is 2, but make the third element g2^3 instead of g2^4.
                g2: vec![G2::from(g2_1), G2::from(g2_2), G2::from(g2_3)],
            },
            pot_pubkey: G2::from(g2_2),
            bls_signature: BlsSignature::empty(),
        };
        assert_eq!(
            transcript
                .verify::<DefaultEngine>(&contribution)
                .err()
                .unwrap(),
            G2PairingFailed
        );
    }

    #[test]
    fn test_verify_wrong_g1_point_count() {
        let transcript = Transcript::new(3, 3);
        let mut contribution = transcript.contribution();
        contribution.powers.g1 = contribution.powers.g1[0..2].to_vec();
        let result = transcript
            .verify::<DefaultEngine>(&contribution)
            .err()
            .unwrap();
        assert_eq!(result, UnexpectedNumG1Powers(3, 2));
    }

    #[test]
    fn test_verify_wrong_g2_point_count() {
        let transcript = Transcript::new(3, 3);
        let mut contribution = transcript.contribution();
        contribution.powers.g2 = contribution.powers.g2[0..2].to_vec();
        let result = transcript
            .verify::<DefaultEngine>(&contribution)
            .err()
            .unwrap();
        assert_eq!(result, UnexpectedNumG2Powers(3, 2));
    }

    #[test]
    fn verify_inclusion() {
        let json = serde_json::json!({
            "numG1Powers": 4,
            "numG2Powers": 2,
            "powersOfTau": {
                "G1Powers": [
                    "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
                    "0x962dffcca938bfe9cc11ab949c73e1b742ca2fe2f7122170e7ed8ceaea9cf57c411743a5ac4c48d7405f397b63d36a25",
                    "0xa57913e7354d2bdbb631e7b270ad9b0fd34c8ee177c5f0903024cc1da1221fa65c92ba515473aa248137dfc510d5d4c9",
                    "0xb2581616a7420d485eee433d355540fd2d9f441a7864b168ad0e068abf4772fa2f644a192b3953616f9fbd5ac88dcd64",

                ],
                "G2Powers": [
                    "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                    "0x8bab27ba31974bfd253d0d37e8ec7c580fa5cc9dfd81eb2e6faae3c4b38b3efcf1e9f3513a0b4031662bbabefe656614190d96e2503d3c68d44324722f00d3abb1b4ec0ba7aa1f4a8595487649912f87ea8f6761648425e9b9baa5a46e18f2c9",
                ],
            },
            "witness": {
                "runningProducts": [
                    "0x9938667a3807b2bba879c10272b0470507cb5926784976d34a440f6ef1aa0cad8a6963c790642a5e76e67cb6471ee075",
                    "0x94d3d149a60414d74e1e60fd1bb4d08ffef7860d86e698439ebbea8614d7ece57d32a1f9be83389bdf7c64846af2513d",
                    "0x94d3d149a60414d74e1e60fd1bb4d08ffef7860d86e698439ebbea8614d7ece57d32a1f9be83389bdf7c64846af2513d",
                    "0xa6ed552088642b976df969e47dc6503e33450744de1b358cafdd610dda3edbfc92efc98c77a4960010a89fa60d0dd127",
                    "0xb4d01655876e28edfa71521ab9fc5d916d9f3ea1c51477c7f912501246a9a7643d2f4ae971563e98dfbdd28df764bedd",
                    "0x962dffcca938bfe9cc11ab949c73e1b742ca2fe2f7122170e7ed8ceaea9cf57c411743a5ac4c48d7405f397b63d36a25"
                ],
                "potPubkeys": [
                    "0xb60f0783433e610a3299d8c7e021f1d9201ff3945e86cdb1887b7799dde67f51dbba932100bdc504fd3c43748ef244db16c1ed2975ce432c21ce64d9795367a901468930b4e5e53501532251445de13e81be7f6c4e1381ba669c26c48f2cfdff",
                    "0x84006b5a3335426c753ed749e32c5942ef653ffede3e086d68d51476fdc3f81be58c7ebffc2866bbdfa1bef99c351a6c0e41681a14f8b6fac97e0069be1c482d14da947d2fdd02459a3e7630a7f0e4574a51c03df0792cb83cbc8a2fe792b84b",
                    "0x93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
                    "0x95b5376cc7c02b45b6f0180523ae3727f927c1def197c022ce7301697cd8f320503116a3c808bd729b854ea96fa6d2a013e255b569bf22a8fb8ee78665994e5ed73d17eb9bfbb9a36fa7ecf62742eb5f18368f801ff49956319312fa895608ec",
                    "0x88bd971ac00d2a3c47a501048f49cd9867f275a69618c4f5b8e8050578dd3776599754e0eff55ddfe7f45be90a4e56a208557f8f9baf0083b225f6229eb718a1437de56183d826e8abbf480cdf5560c82f4222c08dfa8d1061f9d6079cf624ec",
                    "0xb631d2eb6a1313c748ca9ea28a74363b23b6268a5fd5bdf3cebd502a77c5fdc0215b3c7b6652e91234d47eefc71d099b115cb0f89a1e42ec637506c949d33bfd0737e742844eb530a4df38cba7fd168ddc0ac9514e8b9dacb65c5675f0651d69"
                ],
                "blsSignatures": [""],
            }
        });
        let t = serde_json::from_value::<Transcript>(json).unwrap();
        let result = t.verify_inclusion::<DefaultEngine>(1);
        assert_eq!(result, Ok(()));
    }
}
