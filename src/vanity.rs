use coins_bip39::{wordlist::English, Mnemonic};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::RegexBuilder;
use std::{sync::Arc, thread};

use crate::utils::{en_mnemonic_to_ja, is_hex, mnemonic_to_addr};
use crate::MatchMethod;

pub fn vanity_search(
    method: MatchMethod,
    threads: Option<usize>,
    stop_when_found: bool,
    case_sensitive: bool,
    lang: crate::MnemonicLang,
) {
    let matcher: Arc<dyn Fn(&str) -> bool + Send + Sync> = match method {
        MatchMethod {
            start_with: Some(start_with),
            ..
        } => {
            let start_with = format!("0X{}", normalize_search_text(&start_with, case_sensitive));
            if case_sensitive {
                Arc::new(move |a: &str| a.starts_with(&start_with))
            } else {
                Arc::new(move |a: &str| a.to_uppercase().starts_with(&start_with))
            }
        }
        MatchMethod {
            contains: Some(contains),
            ..
        } => {
            let contains = normalize_search_text(&contains, case_sensitive);
            if case_sensitive {
                Arc::new(move |a: &str| a.contains(&contains))
            } else {
                Arc::new(move |a: &str| a.to_uppercase().contains(&contains))
            }
        }
        MatchMethod {
            regex: Some(regex), ..
        } => {
            let re = RegexBuilder::new(&regex)
                .case_insensitive(!case_sensitive)
                .build()
                .unwrap();
            Arc::new(move |a: &str| re.is_match(&a.replace("0x", "CC")))
        }
        _ => panic!("Invalid match method"),
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

fn normalize_search_text(text: &str, case_sensitive: bool) -> String {
    if !is_hex(text) {
        panic!("CCID must be a HEX (0-9, A-F) string");
    } else if text.len() > 40 {
        panic!("Max CCID length is 40 excluding 'CC' prefix");
    }
    if case_sensitive {
        text.to_string()
    } else {
        text.to_uppercase()
    }
}
