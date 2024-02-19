use clap::{Parser, Subcommand, ValueEnum};

mod vanity;
use vanity::vanity_search;

pub mod utils;
use utils::*;

#[derive(Clone, ValueEnum)]
pub enum MnemonicLang {
    En,
    Ja,
}

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

// Enum ArgGroup?
// https://github.com/clap-rs/clap/issues/2621
#[derive(Parser, Clone)]
#[group(required = true, multiple = false)]
struct MatchMethod {
    /// Find addresses that start with this string
    #[clap(short, long, value_name = "HEX")]
    start_with: Option<String>,

    /// Find addresses that contain this string
    #[clap(short, long, value_name = "HEX")]
    contains: Option<String>,

    /// Match regular expression (Search includes "CC" prefix)
    #[clap(short, long, value_name = "REGEX")]
    regex: Option<String>,
}

#[derive(Subcommand)]
enum SubCommand {
    /// Generate a new CCID
    Keygen {
        /// Specify the mnemonic language
        #[clap(short, long, value_name = "MNEMONIC_LANG", value_enum, default_value_t = MnemonicLang::En)]
        lang: MnemonicLang,
    },
    /// Search for a vanity CCID
    VanitySearch {
        #[clap(flatten)]
        match_method: MatchMethod,
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
            let entity = generate_ccid::<coins_bip39::English>(lang).unwrap();
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
            vanity_search(match_method, threads, stop_when_found, case_sensitive, lang);
        }
        SubCommand::PhraseToCcid { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                _ => mnemonic,
            };
            println!("{}", phrase_to_ccid_str(&mnemonic).unwrap());
        }
        SubCommand::PhraseToPrivkey { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                _ => mnemonic,
            };
            println!("{}", phrase_to_privkey_str(&mnemonic).unwrap());
        }
        SubCommand::PhraseToPubkey { mnemonic } => {
            let mnemonic = match detect_mnemonic_lang(&mnemonic) {
                MnemonicLang::Ja => ja_mnemonic_to_en(&mnemonic),
                _ => mnemonic,
            };
            println!("{}", phrase_to_pubkey_str(&mnemonic).unwrap());
        }
        SubCommand::PrivkeyToCcid { privkey } => {
            println!("{}", privkey_to_ccid_str(&privkey).unwrap());
        }
        SubCommand::PrivkeyToPubkey { privkey } => {
            println!("{}", privkey_to_pubkey_str(&privkey).unwrap());
        }
        SubCommand::PubkeyToCcid { pubkey } => {
            println!("{}", pubkey_to_ccid_str(&pubkey).unwrap());
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
