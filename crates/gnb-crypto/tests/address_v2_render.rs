//! Explicit v2 rendering and bounded transcription-error checks.
use gnb_crypto::address::{destination_script, Address, Network, PolicyAddress};

const SINGLE_MAIN: &str = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw";
const SINGLE_TEST: &str = "tgnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtxkpzc";
const POLICY_MAIN: &str = "gnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqggmvny";
const POLICY_TEST: &str = "tgnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqht5fkx";

fn policy_script() -> Vec<u8> {
    let mut script = vec![2];
    script.extend_from_slice(&[0; 32]);
    script
}

#[test]
fn explicit_bech32m_rendering_matches_independent_vectors() {
    for (network, single, policy) in [
        (Network::Mainnet, SINGLE_MAIN, POLICY_MAIN),
        (Network::Testnet, SINGLE_TEST, POLICY_TEST),
    ] {
        assert_eq!(Address::from_hash([0; 20], network).to_bech32m(), single);
        assert_eq!(
            PolicyAddress::from_script(&policy_script(), network)
                .unwrap()
                .to_bech32m(),
            policy
        );
    }
}

#[test]
fn every_single_ascii_character_substitution_is_rejected() {
    // A finite transcription-error check: 20,274 candidates, no network/I/O.
    let mut checked = 0;
    for valid in [SINGLE_MAIN, SINGLE_TEST, POLICY_MAIN, POLICY_TEST] {
        for i in 0..valid.len() {
            for replacement in 33..=126 {
                if valid.as_bytes()[i] == replacement {
                    continue;
                }
                let mut changed = valid.as_bytes().to_vec();
                changed[i] = replacement;
                let changed = std::str::from_utf8(&changed).unwrap();
                assert!(destination_script(changed).is_err(), "{valid} -> {changed}");
                assert!(Address::parse(changed).is_err());
                assert!(PolicyAddress::parse(changed).is_err());
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 20_274);
}
