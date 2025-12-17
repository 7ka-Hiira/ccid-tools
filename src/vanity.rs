use coins_bip39::{wordlist::English, Mnemonic};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::RegexBuilder;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::{sync::Arc, thread};

use crate::utils::{mnemonic_to_addr_fast, translate_mnemonic, CC_ADDR_PREFIX};
use crate::MatchMethod::{self, Contains, EndsWith, Regex, StartsWith};

const PRINT_COUNT: u64 = 50000;

pub fn lookup(
    method: MatchMethod,
    threads: Option<usize>,
    stop_when_found: bool,
    lang: crate::MnemonicLang,
) {
    let method = validate_method(method);
    let matcher: Arc<dyn Fn(&str) -> bool + Send + Sync> = match method {
        StartsWith(hex) => Arc::new(move |a: &str| a.starts_with(&hex)),
        EndsWith(hex) => Arc::new(move |a: &str| a.ends_with(&hex)),
        Contains(hex) => Arc::new(move |a: &str| a.contains(&hex)),
        Regex(regex) => {
            let re = RegexBuilder::new(&regex).build().unwrap_or_else(|e| {
                panic!("Invalid regex: {e}");
            });
            Arc::new(move |a: &str| re.is_match(a))
        }
    };

    let threads_num = threads.unwrap_or(num_cpus::get()).max(1);
    println!("Searching using {threads_num} threads");

    let counter = Arc::new(AtomicU64::new(0));

    let stop_flag = Arc::new(AtomicBool::new(false));

    let handles = (0..threads_num)
        .map(|_| {
            let matcher = Arc::clone(&matcher);
            let counter = Arc::clone(&counter);
            let stop_flag = Arc::clone(&stop_flag);
            thread::spawn(move || {
                worker(&matcher, stop_when_found, lang, &counter, &stop_flag);
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
    stop_flag: &AtomicBool,
) {
    let mut rng = ChaCha20Rng::from_entropy();
    while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
        let count = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % PRINT_COUNT == 0 {
            println!("Attempt: {count}");
        }
        if let Some((mnemonic, addr)) = genkey_attempt(matcher, &mut rng) {
            if stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let mnemonic = translate_mnemonic(&mnemonic, lang).unwrap_or_else(|e| {
                panic!("Failed to translate mnemonic: {e}");
            });
            println!("Mnemonic: {mnemonic}\nAddress: {addr}\n");
            if stop_when_found {
                stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
                return;
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

fn validate_method(method: MatchMethod) -> MatchMethod {
    let validate = |text: &str| -> String {
        let text_lower = text.to_lowercase();
        let bech32regex = regex::Regex::new(r"^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]*$").unwrap();
        assert!(
                bech32regex.is_match(&text_lower),
                "\n*** ERROR ***\nInvalid characters in search string.\nAllowed: 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'\n*************\n"
            );
        text_lower
    };
    match method {
        StartsWith(text) => StartsWith(format!("{}{}", CC_ADDR_PREFIX, validate(&text))),
        EndsWith(text) => EndsWith(validate(&text)),
        Contains(text) => Contains(validate(&text)),
        Regex(_) => method,
    }
}
