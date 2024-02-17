use clap::{Parser, Subcommand};
use coins_bip32::ecdsa::SigningKey;
use coins_bip39::{mnemonic::Mnemonic, English};
use std::{str::FromStr, thread};

pub mod utils;
mod vanity;
use utils::*;
use vanity::find_ccid_from_mnemonic;

#[derive(Parser)]
#[clap(
    version = env!("CARGO_PKG_VERSION"),
    author = env!("CARGO_PKG_AUTHORS"),
    about = env!("CARGO_PKG_DESCRIPTION"),
)]
struct Arg {
    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Parser, Clone)]
#[group(required = true, multiple = false)]
struct MatchMethod {
    /// Find addresses that start with this string
    #[clap(short, long, value_name = "HEX")]
    start_with: Option<String>,
    /// Find addresses that contain this string
    #[clap(short, long, value_name = "HEX")]
    contains: Option<String>,
    /// Match regular expression
    #[clap(long, value_name = "REGEX")]
    regex: Option<String>,
}

#[derive(Subcommand)]
enum SubCommand {
    Generate {},
    Vanity {
        #[clap(flatten)]
        match_method: MatchMethod,
        /// Number of threads to use
        #[clap(short = 'j', long, value_name = "THREAD_NUM")]
        threads: Option<usize>,
    },
    Phrase2ccid {
        /// Mnemonic phrase
        mnemonic: String,
    },
    Phrase2privkey {
        /// Mnemonic phrase
        mnemonic: String,
    },
    Phrase2pubkey {
        /// Mnemonic phrase
        mnemonic: String,
    },
    Privkey2ccid {
        /// Private key
        privkey: String,
    },
    Privkey2pubkey {
        /// Private key
        privkey: String,
    },
    Pubkey2ccid {
        /// Public key
        pubkey: String,
    },
}

fn main() {
    let args: Arg = Arg::parse();
    match args.subcommand {
        SubCommand::Generate {} => {
            let mnemonic: Mnemonic<English> = Mnemonic::new(&mut rand::thread_rng());
            let privkey = hex_encode(mnemonic2privkey(&mnemonic).to_bytes().to_vec().as_ref());
            let ccid = mnemonic2addr(&mnemonic).to_string().replace("0x", "CC");
            println!(
                "Mnemonic: {}\nPrivateKey: {}\nAddress: {}",
                mnemonic.to_phrase(),
                privkey,
                ccid
            );
        }
        SubCommand::Vanity {
            match_method,
            threads,
        } => {
            let mut method = MatchMethod {
                start_with: match_method.start_with,
                contains: match_method.contains,
                regex: match_method.regex,
            };
            if let Some(text) = method.start_with {
                if !text.to_uppercase().starts_with("CC") {
                    panic!("CCID must starts with 'CC'")
                }
                if !text.to_uppercase().chars().all(|c| c.is_ascii_hexdigit()) {
                    panic!("CCID must be a HEX (0-9, A-F) string")
                }
                method.start_with = Some(text.to_uppercase());
            } else if let Some(text) = method.contains {
                if !text.to_uppercase().chars().all(|c| c.is_ascii_hexdigit()) {
                    panic!("CCID must be a HEX (0-9, A-F) string")
                }
                method.contains = Some(text.to_uppercase());
            }
            let mut threads_num = threads.unwrap_or(num_cpus::get());
            if threads_num == 0 {
                threads_num = num_cpus::get();
            }
            for _ in 0..threads_num - 1 {
                let m = method.clone();
                thread::spawn(move || {
                    find_ccid_from_mnemonic(m);
                });
            }
            find_ccid_from_mnemonic(method);
        }
        SubCommand::Phrase2ccid { mnemonic } => {
            let mnemonic: Mnemonic<English> = Mnemonic::from_str(&mnemonic).unwrap();
            let ccid = mnemonic2addr(&mnemonic).to_string().replace("0x", "CC");
            println!("Address: {}", ccid);
        }
        SubCommand::Phrase2privkey { mnemonic } => {
            let mnemonic: Mnemonic<English> = Mnemonic::from_str(&mnemonic).unwrap();
            let privkey = hex_encode(mnemonic2privkey(&mnemonic).to_bytes().as_ref());
            println!("PrivateKey: {}", privkey);
        }
        SubCommand::Phrase2pubkey { mnemonic } => {
            let mnemonic: Mnemonic<English> = Mnemonic::from_str(&mnemonic).unwrap();
            let privkey = mnemonic2privkey(&mnemonic);
            let pubkey = privkey2pubkey(privkey);
            println!("PublicKey: {}", hex_encode(&pubkey));
        }
        SubCommand::Privkey2ccid { privkey } => {
            let key = SigningKey::from_slice(&hex_decode(&privkey)).unwrap();
            let addr = privkey2addr(key);
            let ccaddr = addr.to_string().replace("0x", "CC");
            println!("Address: {}", ccaddr);
        }
        SubCommand::Privkey2pubkey { privkey } => {
            let key = SigningKey::from_slice(&hex_decode(&privkey)).unwrap();
            let pubkey = privkey2pubkey(key);
            println!("PublicKey: {}", hex_encode(&pubkey));
        }
        SubCommand::Pubkey2ccid { pubkey } => {
            let addr = pubkey2addr(&hex_decode(&pubkey));
            let ccaddr = addr.to_string().replace("0x", "CC");
            println!("Address: {}", ccaddr);
        }
    }
}
