use coins_bip39::{wordlist::English, Mnemonic};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::RegexBuilder;
use std::{sync::Arc, thread};

use crate::utils::{en_mnemonic_to_ja, mnemonic_to_addr};
use crate::MatchMethod::{self, *};

pub fn vanity_search(
    method: MatchMethod,
    threads: Option<usize>,
    stop_when_found: bool,
    case_sensitive: bool,
    lang: crate::MnemonicLang,
) {
    let method = validate_and_normalize_method(method, case_sensitive);
    let matcher: Arc<dyn Fn(&str) -> bool + Send + Sync> = match (method, case_sensitive) {
        (StartsWith(hex), false) => Arc::new(move |a: &str| a.to_lowercase().starts_with(&hex)),
        (StartsWith(hex), true) => Arc::new(move |a: &str| a.starts_with(&hex)),
        (EndsWith(hex), false) => Arc::new(move |a: &str| a.to_lowercase().ends_with(&hex)),
        (EndsWith(hex), true) => Arc::new(move |a: &str| a.ends_with(&hex)),
        (Contains(hex), false) => Arc::new(move |a: &str| a.to_lowercase().contains(&hex)),
        (Contains(hex), true) => Arc::new(move |a: &str| a.contains(&hex)),
        (Regex(regex), case_sensitive) => {
            let re = RegexBuilder::new(&regex)
                .case_insensitive(!case_sensitive)
                .build()
                .unwrap_or_else(|e| {
                    eprintln!("Invalid regex: {}", e);
                    std::process::exit(1);
                });
            Arc::new(move |a: &str| re.is_match(&a.replace("0x", "CC")))
        }
    };

    let threads_num = threads.unwrap_or(num_cpus::get()).max(1);
    println!("Searching using {} threads", threads_num);

    let mut handles = vec![];
    for _ in 0..threads_num {
        let matcher = Arc::clone(&matcher);
        let lang = lang.clone();
        let handle = thread::spawn(move || {
            let mut rng = ChaCha20Rng::from_entropy();
            loop {
                if let Some((mnemonic, addr)) = search(&matcher, &mut rng) {
                    let mnemonic = if matches!(lang, crate::MnemonicLang::Ja) {
                        en_mnemonic_to_ja(&mnemonic)
                    } else {
                        mnemonic
                    };
                    println!("Mnemonic: {mnemonic}\nAddress: {addr}\n");
                    if stop_when_found {
                        std::process::exit(0);
                    }
                }
            }
        });
        handles.push(handle);
    }
    handles.into_iter().for_each(|h| h.join().unwrap());
}

fn search(
    is_match: &Arc<dyn Fn(&str) -> bool + Send + Sync>,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Option<(String, String)> {
    let mnemonic: Mnemonic<English> = Mnemonic::new(rng);
    let addr = mnemonic_to_addr(&mnemonic).unwrap();
    if is_match(&addr.to_string()) {
        Some((mnemonic.to_phrase(), addr.to_string().replace("0x", "CC")))
    } else {
        None
    }
}

fn validate_and_normalize_method(method: MatchMethod, case_sensitive: bool) -> MatchMethod {
    match &method {
        StartsWith(text) | EndsWith(text) | Contains(text) => {
            if !text.to_uppercase().chars().all(|c| c.is_ascii_hexdigit()) {
                eprintln!("CCID must be a HEX (0-9, A-F) string");
                std::process::exit(1);
            }
            if text.len() > 40 {
                eprintln!("Max CCID length is 40 excluding 'CC' prefix");
                std::process::exit(1);
            }
            if case_sensitive {
                match &method {
                    StartsWith(_) => StartsWith(format!("0x{}", text)),
                    _ => method,
                }
            } else {
                match &method {
                    StartsWith(_) => StartsWith(format!("0x{}", text).to_lowercase()),
                    EndsWith(_) => EndsWith(text.to_lowercase()),
                    Contains(_) => Contains(text.to_lowercase()),
                    _ => method,
                }
            }
        }
        _ => method,
    }
}
