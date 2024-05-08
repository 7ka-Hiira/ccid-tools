use coins_bip39::{wordlist::English, Mnemonic};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::RegexBuilder;
use std::{sync::Arc, thread};

use crate::utils::{en_mnemonic_to_ja, mnemonic_to_addr_unchecked};
use crate::MatchMethod::{self, Contains, EndsWith, Regex, StartsWith};

// ゆるして
static mut COUNT: u64 = 0;
const PRINT_COUNT: u64 = 50000;

pub fn lookup(
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
                    panic!("Invalid regex: {e}");
                });
            Arc::new(move |a: &str| re.is_match(a))
        }
    };

    let threads_num = threads.unwrap_or(num_cpus::get()).max(1);
    println!("Searching using {threads_num} threads");

    let mut handles = vec![];
    for _ in 0..threads_num {
        let matcher = Arc::clone(&matcher);
        let handle = thread::spawn(move || {
            worker(&matcher, stop_when_found, lang);
        });
        handles.push(handle);
    }
    handles.into_iter().for_each(|h| h.join().unwrap());
}

fn worker(
    matcher: &Arc<dyn Fn(&str) -> bool + Send + Sync>,
    stop_when_found: bool,
    lang: crate::MnemonicLang,
) {
    let mut rng = ChaCha20Rng::from_entropy();
    loop {
        unsafe {
            COUNT += 1;
            if COUNT % PRINT_COUNT == 0 {
                println!("Attempts: {}", COUNT);
            }
        }
        if let Some((mnemonic, addr)) = genkey_attempt(matcher, &mut rng) {
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
}

#[inline]
fn genkey_attempt(
    matcher: &Arc<dyn Fn(&str) -> bool + Send + Sync>,
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Option<(String, String)> {
    let mnemonic: Mnemonic<English> = Mnemonic::new(rng);
    let addr = mnemonic_to_addr_unchecked(&mnemonic);
    if matcher(&addr.to_string()) {
        Some((mnemonic.to_phrase(), addr.to_string()))
    } else {
        None
    }
}

fn validate_and_normalize_method(method: MatchMethod, case_sensitive: bool) -> MatchMethod {
    match &method {
        StartsWith(text) | EndsWith(text) | Contains(text) => {
            let bech32regex = regex::Regex::new(r"^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{1,38}$").unwrap();
            assert!(
                bech32regex.is_match(text),
                "Invalid bech32 character or length. Bech32 characters are 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'"
            );
            if case_sensitive {
                match &method {
                    StartsWith(_) => StartsWith(format!("con1{text}")),
                    _ => method,
                }
            } else {
                match &method {
                    StartsWith(_) => StartsWith(format!("con1{text}").to_lowercase()),
                    EndsWith(_) => EndsWith(text.to_lowercase()),
                    Contains(_) => Contains(text.to_lowercase()),
                    Regex(_) => method,
                }
            }
        }
        Regex(_) => method,
    }
}

