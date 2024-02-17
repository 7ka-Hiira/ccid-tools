use coins_bip39::{wordlist::English, Mnemonic};
use regex::Regex;
use std::thread;

use crate::utils::{is_hex, mnemonic_to_addr, start_with_cc};
use crate::MatchMethod;

pub fn vanity_search(match_method: MatchMethod, threads: Option<usize>) {
    let mut method = MatchMethod {
        start_with: match_method.start_with,
        contains: match_method.contains,
        regex: match_method.regex,
    };

    // Validate match method
    if let Some(text) = method.start_with {
        if !is_hex(&text) {
            panic!("CCID must be a HEX (0-9, A-F) string");
        } else if !start_with_cc(&text) {
            panic!("CCID must start with 'CC'");
        } else if text.len() > 42 {
            panic!("Max CCID length is 42");
        }
        method.start_with = Some(text.to_uppercase());
    }
    if let Some(text) = method.contains {
        if !is_hex(&text) {
            panic!("CCID must be a HEX (0-9, A-F) string");
        } else if text.len() > 42 {
            panic!("Max CCID length is 42");
        } else if text.len() > 40 && start_with_cc(&text) {
            panic!("Max CCID without 'CC' prefix is 40");
        }
        method.contains = Some(text.to_uppercase());
    }

    let threads_num = threads.unwrap_or(num_cpus::get()).max(1);
    println!("Searching with {} threads", threads_num);

    for _ in 0..threads_num {
        let m = method.clone();
        thread::spawn(|| {
            search_ccid_from_mnemonic(m);
        });
    }
    thread::park();
}

fn search_ccid_from_mnemonic(matchmethod: MatchMethod) {
    let re = matchmethod.regex.as_ref().map(|r| Regex::new(r).unwrap());
    loop {
        let mnemonic: Mnemonic<English> = Mnemonic::new(&mut rand::thread_rng());
        let addr = mnemonic_to_addr(&mnemonic);

        if match_check(&matchmethod, &addr.to_string().replace("0x", "CC"), &re) {
            println!(
                "Mnemonic: {}\nAddress: {}\n",
                mnemonic.to_phrase(),
                addr.to_string().replace("0x", "CC")
            );
        }
    }
}

fn match_check(matchmethod: &MatchMethod, addr: &str, re: &Option<Regex>) -> bool {
    match matchmethod {
        MatchMethod {
            start_with: Some(text),
            ..
        } if addr.to_uppercase().starts_with(text) => true,
        MatchMethod {
            contains: Some(text),
            ..
        } if addr.to_uppercase().contains(text) => true,
        MatchMethod { regex: Some(_), .. } if re.to_owned().unwrap().is_match(addr) => true,
        _ => false,
    }
}
