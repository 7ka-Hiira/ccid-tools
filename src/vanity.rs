use coins_bip39::{wordlist::English, Mnemonic};
use regex::Regex;

use crate::utils::mnemonic2addr;
use crate::MatchMethod;

pub fn find_ccid_from_mnemonic(matchmethod: MatchMethod) {
    let mut rng = rand::thread_rng();
    let re = if let Some(r) = &matchmethod.regex {
        Regex::new(r).unwrap()
    } else {
        Regex::new("").unwrap()
    };
    loop {
        let mnemonic: Mnemonic<English> = Mnemonic::new(&mut rng);
        let addr = mnemonic2addr(&mnemonic);

        if !match_check(
            &matchmethod,
            &addr.to_string().replace("0x", "CC").to_uppercase(),
            &re,
        ) {
            continue;
        }

        println!(
            "Mnemonic: {}\nAddress: {}\n",
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
