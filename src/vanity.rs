use crate::MatchMethod;
use alloy_signer::coins_bip39::wordlist::English;
use alloy_signer::coins_bip39::Mnemonic;
use alloy_signer::k256::ecdsa::SigningKey;
use alloy_signer::utils::secret_key_to_address;
use regex::Regex;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

pub fn find_ccid_from_mnemonic(matchmethod: MatchMethod) {
    let mut rng = rand::thread_rng();
    let re = if let Some(r) = &matchmethod.regex {
        Regex::new(r).unwrap()
    } else {
        Regex::new("").unwrap()
    };
    loop {
        let mnemonic: Mnemonic<English> = Mnemonic::new(&mut rng);
        let priv_key = mnemonic.derive_key(DEFAULT_DERIVATION_PATH, None).unwrap();
        let key: &coins_bip32::prelude::SigningKey = priv_key.as_ref();
        let addr = secret_key_to_address(&SigningKey::from_bytes(&key.to_bytes()).unwrap());

        if !match_check(
            &matchmethod,
            &addr.to_string().replace("0x", "CC").to_uppercase(),
            &re,
        ) {
            continue;
        }

        println!(
            "Mnemonic: {}\nAddress: {:?}",
            mnemonic.to_phrase(),
            addr.to_string().replace("0x", "CC")
        );
    }
}

fn match_check(matchmethod: &MatchMethod, addr: &str, re: &Regex) -> bool {
    if let Some(start_with) = &matchmethod.start_with {
        if addr.starts_with(start_with) {
            return true;
        }
    } else if let Some(contains) = &matchmethod.contains {
        if addr.contains(contains) {
            return true;
        }
    } else if re.is_match(addr) {
        return true;
    }
    false
}
