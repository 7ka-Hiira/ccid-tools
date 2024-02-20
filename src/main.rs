use clap::{Parser, Subcommand, ValueEnum};

mod vanity;
use vanity::vanity_search;

pub mod utils;
use utils::*;

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

#[derive(Clone, ValueEnum)]
pub enum MnemonicLang {
    En,
    Ja,
}

// Parse into Enum MatchMethod
// Enum ArgGroup is not supported yet (2023-02-20)
// https://github.com/clap-rs/clap/issues/2621
#[derive(Parser, Clone)]
#[group(required = true, multiple = false)]
struct MatchMethodStruct {
    /// Find addresses that starts with this string
    #[clap(short, long, value_name = "HEX")]
    starts_with: Option<String>,

    /// Find addresses that contains this string
    #[clap(short, long, value_name = "HEX")]
    contains: Option<String>,

    /// Find addresses that matches this regex (including 'CC' prefixs)
    #[clap(short, long, value_name = "REGEX")]
    regex: Option<String>,
}
enum MatchMethod {
    StartsWith(String),
    Contains(String),
    Regex(String),
}

#[derive(Subcommand)]
enum SubCommand {
    /// Generate an entity
    Keygen {
        /// Specify the mnemonic language
        #[clap(short, long, value_name = "MNEMONIC_LANG", value_enum, default_value_t = MnemonicLang::En)]
        lang: MnemonicLang,
    },
    /// Search for a vanity CCID
    VanitySearch {
        #[clap(flatten)]
        match_method: MatchMethodStruct,
        /// Number of threads to use
        #[clap(short = 'j', long, value_name = "THREAD_NUM")]
        threads: Option<usize>,
        /// Exits after the first match
        #[clap(short = 'x', long, value_name = "BOOL", default_value_t = false)]
        stop_when_found: bool,
        /// Enable case-sensitive search
        #[clap(short, long, value_name = "BOOL", default_value_t = false)]
        case_sensitive: bool,
        /// Specify the mnemonic language
        #[clap(short, long, value_name = "MNEMONIC_LANG", value_enum, default_value_t = MnemonicLang::En)]
        lang: MnemonicLang,
    },
    /// Derive a CCID from a mnemonic phrase
    PhraseToCcid {
        /// Mnemonic phrase
        #[clap(value_name = "MNEMONIC")]
        mnemonic: String,
    },
    /// Derive a private key from a mnemonic phrase
    PhraseToPrivkey {
        /// Mnemonic phrase
        #[clap(value_name = "MNEMONIC")]
        mnemonic: String,
    },
    /// Derive a public key from a mnemonic phrase
    PhraseToPubkey {
        /// Mnemonic phrase
        #[clap(value_name = "MNEMONIC")]
        mnemonic: String,
    },
    /// Derive a CCID from a private key
    PrivkeyToCcid {
        /// Private key
        #[clap(value_name = "HEX_PRIVATE_KEY")]
        privkey: String,
    },
    /// Derive a public key from a private key
    PrivkeyToPubkey {
        /// Private key
        #[clap(value_name = "HEX_PRIVATE_KEY")]
        privkey: String,
    },
    /// Derive a CCID from a public key
    PubkeyToCcid {
        /// Public key
        #[clap(value_name = "HEX_PUBLIC_KEY")]
        pubkey: String,
    },
    TranslatePhrase {
        /// Specify the target mnemonic language
        #[clap(value_name = "TARGET_LANG", value_enum, required = true)]
        target_lang: MnemonicLang,
        /// Mnemonic phrase
        #[clap(value_name = "MNEMONIC", required = true)]
        mnemonic: String,
    },
}

fn main() {
    let args = Arg::parse();
    match args.subcommand {
        SubCommand::Keygen { lang } => {
            let entity = generate_entity::<coins_bip39::English>(lang).unwrap_or_else(|e| {
                eprintln!("Failed to generate entity: {}", e);
                std::process::exit(1);
            });
            println!(
                "Mnemonic: {}\nPrivate Key: {}\nCCID: {}",
                entity.0, entity.1, entity.2
            );
        }
        SubCommand::VanitySearch {
            match_method,
            threads,
            stop_when_found,
            case_sensitive,
            lang,
        } => {
            // Parse MatchMethodStruct to MatchMethod
            let match_method = match match_method {
                MatchMethodStruct {
                    starts_with: Some(starts_with),
                    ..
                } => MatchMethod::StartsWith(starts_with),
                MatchMethodStruct {
                    contains: Some(contains),
                    ..
                } => MatchMethod::Contains(contains),
                MatchMethodStruct {
                    regex: Some(regex), ..
                } => MatchMethod::Regex(regex),
                _ => {
                    eprintln!("One of --starts-with, --contains, or --regex must be specified");
                    std::process::exit(1);
                }
            };
            vanity_search(match_method, threads, stop_when_found, case_sensitive, lang);
        }
        SubCommand::PhraseToCcid { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                _ => mnemonic,
            };
            println!(
                "{}",
                phrase_to_ccid_str(&mnemonic).unwrap_or_else(|e| {
                    eprintln!("Failed to derive CCID from mnemonic: {}", e);
                    std::process::exit(1);
                })
            );
        }
        SubCommand::PhraseToPrivkey { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                _ => mnemonic,
            };
            println!(
                "{}",
                phrase_to_privkey_str(&mnemonic).unwrap_or_else(|e| {
                    eprintln!("Failed to derive private key from mnemonic: {}", e);
                    std::process::exit(1);
                })
            )
        }
        SubCommand::PhraseToPubkey { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                _ => mnemonic,
            };
            println!(
                "{}",
                phrase_to_pubkey_str(&mnemonic).unwrap_or_else(|e| {
                    eprintln!("Failed to derive public key from mnemonic: {}", e);
                    std::process::exit(1);
                })
            )
        }
        SubCommand::PrivkeyToCcid { privkey } => {
            println!(
                "{}",
                privkey_to_ccid_str(&privkey).unwrap_or_else(|e| {
                    eprintln!("Failed to derive CCID from private key: {}", e);
                    std::process::exit(1);
                })
            );
        }
        SubCommand::PrivkeyToPubkey { privkey } => {
            println!(
                "{}",
                privkey_to_pubkey_str(&privkey).unwrap_or_else(|e| {
                    eprintln!("Failed to derive public key from private key: {}", e);
                    std::process::exit(1);
                })
            );
        }
        SubCommand::PubkeyToCcid { pubkey } => {
            println!(
                "{}",
                pubkey_to_ccid_str(&pubkey).unwrap_or_else(|e| {
                    eprintln!("Failed to derive CCID from public key: {}", e);
                    std::process::exit(1);
                })
            );
        }
        SubCommand::TranslatePhrase {
            target_lang,
            mnemonic,
        } => {
            let source_lang = detect_mnemonic_lang(&mnemonic);
            let result = match (source_lang, target_lang) {
                (MnemonicLang::En, MnemonicLang::Ja) => en_mnemonic_to_ja(&mnemonic),
                (MnemonicLang::Ja, MnemonicLang::En) => ja_mnemonic_to_en(&mnemonic),
                _ => mnemonic,
            };
            println!("{}", result);
        }
    }
}
