use coins_bip39::{wordlist::English, Mnemonic};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use regex::bytes::RegexBuilder;
use std::io::{Cursor, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::{sync::Arc, thread};

use crate::utils::{mnemonic_to_addr_fast, translate_mnemonic, CC_ADDR_PREFIX, CC_ADDR_SIZE};
use crate::MatchMethod::{self, Contains, EndsWith, Regex, StartsWith};

const COUNTER_BATCH_SIZE: u64 = 1000;
// PRINT_SIZE should be multiple of COUNTER_BATCH_SIZE
const PRINT_COUNTER_SIZE: u64 = COUNTER_BATCH_SIZE * 50;

pub fn lookup(
    method: MatchMethod,
    threads: Option<usize>,
    stop_when_found: bool,
    lang: crate::MnemonicLang,
) {
    let mut match_bytes = [0u8; CC_ADDR_SIZE];
    let match_length = validate_method(&method, &mut match_bytes);
    let matcher: Arc<dyn Fn(&[u8]) -> bool + Send + Sync> = match method {
        StartsWith(_) => Arc::new(move |a: &[u8]| a.starts_with(&match_bytes[..match_length])),
        EndsWith(_) => Arc::new(move |a: &[u8]| a.ends_with(&match_bytes[..match_length])),
        Contains(_) => Arc::new(move |a: &[u8]| {
            a.windows(match_length)
                .any(|w| w == &match_bytes[..match_length])
        }),
        Regex(regex) => {
            let re = RegexBuilder::new(&regex)
                .unicode(false)
                .build()
                .unwrap_or_else(|e| {
                    panic!("Invalid regex: {e}");
                });
            Arc::new(move |a: &[u8]| re.is_match(a))
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
    matcher: &Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    stop_when_found: bool,
    lang: crate::MnemonicLang,
    counter: &AtomicU64,
    stop_flag: &AtomicBool,
) {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut buffer = [0u8; CC_ADDR_SIZE];
    while !stop_flag.load(Ordering::Relaxed) {
        for _ in 0..COUNTER_BATCH_SIZE {
            if let Some((mnemonic, addr)) = genkey_attempt(matcher, &mut buffer, &mut rng) {
                if stop_flag.load(Ordering::Relaxed) {
                    return;
                }
                let mnemonic = translate_mnemonic(&mnemonic, lang).unwrap_or_else(|e| {
                    panic!("Failed to translate mnemonic: {e}");
                });
                println!("Mnemonic: {mnemonic}\nAddress: {addr}\n");
                if stop_when_found {
                    stop_flag.store(true, Ordering::Relaxed);
                    return;
                }
            }
        }
        let prev_count = counter.fetch_add(COUNTER_BATCH_SIZE, Ordering::Relaxed);
        let new_count = counter.load(Ordering::Relaxed);
        if prev_count / PRINT_COUNTER_SIZE != new_count / PRINT_COUNTER_SIZE {
            println!("Attempt: {new_count}");
        }
    }
}

#[inline]
fn genkey_attempt(
    matcher: &Arc<dyn Fn(&[u8]) -> bool + Send + Sync>,
    buffer: &mut [u8],
    rng: &mut rand_chacha::ChaCha20Rng,
) -> Option<(String, String)> {
    let mnemonic: Mnemonic<English> = Mnemonic::new(rng);
    let mut cursor = Cursor::new(&mut buffer[..]);
    mnemonic_to_addr_fast(&mnemonic, &mut cursor)
        .expect("Encoding failed: buffer might be too small");
    if matcher(buffer) {
        Some((
            mnemonic.to_phrase(),
            String::from_utf8(buffer.to_vec()).unwrap(),
        ))
    } else {
        None
    }
}

fn validate_method(method: &MatchMethod, match_bytes: &mut [u8]) -> usize {
    let validate = |text: &str| -> String {
        let text_lower = text.to_lowercase();
        let bech32regex = regex::Regex::new(r"^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]*$").unwrap();
        assert!(
                bech32regex.is_match(&text_lower),
                "\n*** ERROR ***\nInvalid characters in search string.\nAllowed: 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'\n*************\n"
            );
        text_lower
    };
    let mut cursor = Cursor::new(&mut match_bytes[..]);
    match method {
        StartsWith(text) => {
            let valid_text = validate(text);
            write!(cursor, "{}{}", CC_ADDR_PREFIX, valid_text)
                .expect("Buffer overflow: Search string is too long");
        }
        EndsWith(text) | Contains(text) => {
            let valid_text = validate(text);
            write!(cursor, "{}", valid_text).expect("Buffer overflow: Search string is too long");
        }
        Regex(_) => (),
    };

    cursor.position() as usize
}
