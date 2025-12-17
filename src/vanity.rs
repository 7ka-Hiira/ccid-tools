use coins_bip39::{wordlist::English, Mnemonic};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::RegexBuilder;
use std::sync::atomic::AtomicU64;
use std::{sync::Arc, thread};

use crate::utils::{mnemonic_to_addr_fast, translate_mnemonic, CC_ADDR_PREFIX};
use crate::MatchMethod::{self, Contains, EndsWith, Regex, StartsWith};

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

    let counter = Arc::new(AtomicU64::new(0));

    let handles = (0..threads_num)
        .map(|_| {
            let matcher = Arc::clone(&matcher);
            let counter = Arc::clone(&counter);
            thread::spawn(move || {
                worker(&matcher, stop_when_found, lang, &counter);
            })
        })
        .collect::<Vec<_>>();
    handles.into_iter().for_each(|h| h.join().unwrap());
}

fn worker(
    matcher: &Arc<dyn Fn(&str) -> bool + Send + Sync>,
    stop_when_found: bool,
    lang: crate::MnemonicLang,
    counter: &AtomicU64,
) {
    let mut rng = ChaCha20Rng::from_entropy();
    loop {
        let count = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % PRINT_COUNT == 0 {
            println!("Attempt: {count}");
        }
        if let Some((mnemonic, addr)) = genkey_attempt(matcher, &mut rng) {
            let mnemonic = translate_mnemonic(&mnemonic, lang).unwrap_or_else(|e| {
                panic!("Failed to translate mnemonic: {e}");
            });
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
    let addr = mnemonic_to_addr_fast(&mnemonic).unwrap_or_else(|e| {
        panic!("Failed to generate address: {e}");
    });
    if matcher(&addr.to_string()) {
        Some((mnemonic.to_phrase(), addr.to_string()))
    } else {
        None
    }
}

fn validate_and_normalize_method(method: MatchMethod, case_sensitive: bool) -> MatchMethod {
    match &method {
        StartsWith(text) | EndsWith(text) | Contains(text) => {
            let bech32regex =
                regex::Regex::new(r"^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{1,38}$").unwrap();
            assert!(
                bech32regex.is_match(&text.to_lowercase()),
                "\n*** ERROR ***\n\
                Invalid Bech32 segment format. Please ensure the following:\n\
                - Only the following characters are allowed: 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'\n\
                - The segment length must not exceed 39 characters.\n\
                *************\n"
            );
            if case_sensitive {
                match &method {
                    StartsWith(_) => StartsWith(format!("{CC_ADDR_PREFIX}{text}")),
                    _ => method,
                }
            } else {
                match &method {
                    StartsWith(_) => StartsWith(format!("{CC_ADDR_PREFIX}{text}").to_lowercase()),
                    EndsWith(_) => EndsWith(text.to_lowercase()),
                    Contains(_) => Contains(text.to_lowercase()),
                    Regex(_) => method,
                }
            }
        }
        Regex(_) => method,
    }
}
