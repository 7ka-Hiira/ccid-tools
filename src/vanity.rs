use coins_bip39::{wordlist::English, Mnemonic};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::Regex;
use std::{sync::Arc, thread};

use crate::utils::{is_hex, mnemonic_to_addr};
use crate::MatchMethod;

pub fn vanity_search(method: MatchMethod, threads: Option<usize>) {
    let matcher: Arc<dyn Fn(&str) -> bool + Send + Sync> = match method {
        MatchMethod {
            start_with: Some(text),
            ..
        } => {
            let text = format!("0X{}", normalize_search_text(&text));
            Arc::new(move |a: &str| a.to_uppercase().starts_with(&text))
        }
        MatchMethod {
            contains: Some(text),
            ..
        } => {
            let text = normalize_search_text(&text);
            Arc::new(move |a: &str| a.to_uppercase().contains(&text))
        }
        MatchMethod { regex: Some(_), .. } => {
            let re = Regex::new(method.regex.unwrap().as_str()).unwrap();
            Arc::new(move |a: &str| re.is_match(a))
        }
        _ => panic!("Invalid match method"),
    };

    let threads_num = threads.unwrap_or(num_cpus::get()).max(1);
    println!("Searching using {} threads", threads_num);

    for _ in 0..threads_num {
        let matcher = Arc::clone(&matcher);
        thread::spawn(move || {
            search(matcher);
        });
    }
    thread::park();
}

fn search(f: Arc<dyn Fn(&str) -> bool + Send + Sync>) {
    let mut rng = ChaCha20Rng::from_entropy();
    loop {
        let mnemonic: Mnemonic<English> = Mnemonic::new(&mut rng);
        let addr = mnemonic_to_addr(&mnemonic);
        if f(&addr.to_string()) {
            println!(
                "Mnemonic: {}\nAddress: {}\n",
                mnemonic.to_phrase(),
                addr.to_string().replace("0x", "CC")
            );
        }
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
