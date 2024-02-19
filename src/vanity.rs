use coins_bip39::{wordlist::English, Mnemonic};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use std::{sync::Arc, thread};

use crate::utils::{en_mnemonic_to_ja, is_hex, mnemonic_to_addr};
use crate::MatchMethod;

pub fn vanity_search(lang: crate::MnemonicLang, method: MatchMethod, threads: Option<usize>) {
    let matcher: Arc<dyn Fn(&str) -> bool + Send + Sync> = match method {
        MatchMethod::StartWith { hex_text } => {
            let hex_text = format!("0X{}", normalize_search_text(&hex_text));
            Arc::new(move |a: &str| a.to_uppercase().starts_with(&hex_text))
        }
        MatchMethod::Contains { hex_text } => {
            let hex_text = normalize_search_text(&hex_text);
            Arc::new(move |a: &str| a.to_uppercase().contains(&hex_text))
        }
        MatchMethod::Regex { regex } => {
            let re = Regex::new(&regex).map_err(|e| e.to_string()).unwrap();
            Arc::new(move |a: &str| re.is_match(a))
        }
    };

    let threads_num = threads.unwrap_or(num_cpus::get()).max(1);
    println!("Searching using {} threads", threads_num);

    for _ in 0..threads_num {
        let matcher = Arc::clone(&matcher);
        let lang = lang.clone();
        thread::spawn(move || loop {
            if let Some((mnemonic, addr)) = search(&matcher) {
                let mnemonic = if matches!(lang, crate::MnemonicLang::Ja) {
                    en_mnemonic_to_ja(&mnemonic)
                } else {
                    mnemonic
                };
                println!("Mnemonic: {mnemonic}\nAddress: {addr}\n");
            };
        });
    }
    thread::park();
}

fn search(f: &Arc<dyn Fn(&str) -> bool + Send + Sync>) -> Option<(String, String)> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mnemonic: Mnemonic<English> = Mnemonic::new(&mut rng);
    let addr = mnemonic_to_addr(&mnemonic);
    if f(&addr.to_string()) {
        Some((mnemonic.to_phrase(), addr.to_string().replace("0x", "CC")))
    } else {
        None
    }
}

fn normalize_search_text(text: &str) -> String {
    if !is_hex(text) {
        panic!("CCID must be a HEX (0-9, A-F) string");
    } else if text.len() > 40 {
        panic!("Max CCID length is 40 excluding 'CC' prefix");
    }
    text.to_uppercase()
}
