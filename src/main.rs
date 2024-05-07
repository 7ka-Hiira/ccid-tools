pub mod utils;
mod vanity;

use clap::{Parser, Subcommand, ValueEnum};
use utils::{
    detect_mnemonic_lang, en_mnemonic_to_ja, generate_entity, ja_mnemonic_to_en,
    mnemonic_to_ccid_str, mnemonic_to_privkey_str, mnemonic_to_pubkey_str, privkey_to_address_str,
    privkey_to_pubkey_str, pubkey_to_address_str,
};

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

#[derive(Clone, Copy, ValueEnum)]
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

    /// Find addresses that ends with this string
    #[clap(short, long, value_name = "HEX")]
    ends_with: Option<String>,

    /// Find addresses that contains this string
    #[clap(short, long, value_name = "HEX")]
    contains: Option<String>,

    /// Find addresses that matches this regex (including 'CC' prefixs)
    #[clap(short, long, value_name = "REGEX")]
    regex: Option<String>,
}
enum MatchMethod {
    StartsWith(String),
    EndsWith(String),
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
    /// Derive a CCID from a mnemonic
    MnemonicToAddress {
        /// Mnemonic
        #[clap(value_name = "MNEMONIC")]
        mnemonic: String,
        // (subkey mode is not supported)
    },
    /// Derive a private key from a mnemonic
    MnemonicToPrivkey {
        /// Mnemonic
        #[clap(value_name = "MNEMONIC")]
        mnemonic: String,
    },
    /// Derive a public key from a mnemonic
    MnemonicToPubkey {
        /// Mnemonic
        #[clap(value_name = "MNEMONIC")]
        mnemonic: String,
    },
    /// Derive a CCID or a CKID from a private key
    PrivkeyToAddress {
        /// Private key
        #[clap(value_name = "HEX_PRIVATE_KEY")]
        privkey: String,
        /// Enable subkey mode
        #[clap(long, value_name = "BOOL", default_value_t = false)]
        subkey: bool,
    },
    /// Derive a public key from a private key
    PrivkeyToPubkey {
        /// Private key
        #[clap(value_name = "HEX_PRIVATE_KEY")]
        privkey: String,
    },
    /// Derive a CCID or a CKID from a public key
    PubkeyToAddress {
        /// Public key
        #[clap(value_name = "HEX_PUBLIC_KEY")]
        pubkey: String,
        /// Enable subkey mode
        #[clap(long, value_name = "BOOL", default_value_t = false)]
        subkey: bool,
    },
    /// Translate a mnemonic to another language
    TranslateMnemonic {
        /// Specify the target mnemonic language
        #[clap(value_name = "TARGET_LANG", value_enum, required = true)]
        target_lang: MnemonicLang,
        /// Mnemonic
        #[clap(value_name = "MNEMONIC", required = true)]
        mnemonic: String,
    },
}

fn main() {
    let args = Arg::parse();
    match args.subcommand {
        SubCommand::Keygen { lang } => {
            let entity = generate_entity::<coins_bip39::English>(&lang).unwrap_or_else(|e| {
                panic!("Failed to generate entity: {e}");
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
                    ends_with: Some(ends_with),
                    ..
                } => MatchMethod::EndsWith(ends_with),
                MatchMethodStruct {
                    contains: Some(contains),
                    ..
                } => MatchMethod::Contains(contains),
                MatchMethodStruct {
                    regex: Some(regex), ..
                } => MatchMethod::Regex(regex),
                _ => {
                    panic!("Invalid match method");
                }
            };
            vanity::lookup(match_method, threads, stop_when_found, case_sensitive, lang);
        }
        SubCommand::MnemonicToAddress { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                MnemonicLang::En => mnemonic,
            };
            println!(
                "{}",
                mnemonic_to_ccid_str(&mnemonic).unwrap_or_else(|e| {
                    panic!("Failed to derive CCID from mnemonic: {e}");
                })
            );
        }
        SubCommand::MnemonicToPrivkey { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                MnemonicLang::En => mnemonic,
            };
            println!(
                "{}",
                mnemonic_to_privkey_str(&mnemonic).unwrap_or_else(|e| {
                    panic!("Failed to derive private key from mnemonic: {e}");
                })
            );
        }
        SubCommand::MnemonicToPubkey { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                MnemonicLang::En => mnemonic,
            };
            println!(
                "{}",
                mnemonic_to_pubkey_str(&mnemonic).unwrap_or_else(|e| {
                    panic!("Failed to derive public key from mnemonic: {e}");
                })
            );
        }
        SubCommand::PrivkeyToAddress { privkey, subkey } => {
            println!(
                "{}",
                privkey_to_address_str(&privkey, subkey).unwrap_or_else(|e| {
                    panic!("Failed to derive CCID from private key: {e}");
                })
            );
        }
        SubCommand::PrivkeyToPubkey { privkey } => {
            println!(
                "{}",
                privkey_to_pubkey_str(&privkey).unwrap_or_else(|e| {
                    panic!("Failed to derive public key from private key: {e}");
                })
            );
        }
        SubCommand::PubkeyToAddress { pubkey, subkey } => {
            println!(
                "{}",
                pubkey_to_address_str(&pubkey, subkey).unwrap_or_else(|e| {
                    panic!("Failed to derive CCID from public key: {e}");
                })
            );
        }
        SubCommand::TranslateMnemonic {
            target_lang,
            mnemonic,
        } => {
            let source_lang = detect_mnemonic_lang(&mnemonic);
            let result = match (source_lang, target_lang) {
                (MnemonicLang::En, MnemonicLang::Ja) => en_mnemonic_to_ja(&mnemonic),
                (MnemonicLang::Ja, MnemonicLang::En) => ja_mnemonic_to_en(&mnemonic),
                _ => mnemonic,
            };
            println!("{result}");
        }
    }
}
