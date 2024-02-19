use clap::{Parser, Subcommand};

mod vanity;
use vanity::vanity_search;

pub mod utils;
use utils::{
    generate_ccid, phrase_to_ccid_str, phrase_to_privkey_str, phrase_to_pubkey_str,
    privkey_to_ccid_str, privkey_to_pubkey_str, pubkey_to_ccid_str,
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
    /// Generate a new CCID
    Keygen {},
    /// Search for a vanity CCID
    VanitySearch {
        #[clap(flatten)]
        match_method: MatchMethod,
        /// Number of threads to use
        #[clap(short = 'j', long, value_name = "THREAD_NUM")]
        threads: Option<usize>,
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
}

fn main() {
    match Arg::parse().subcommand {
        SubCommand::Keygen {} => {
            let entity = generate_ccid::<coins_bip39::English>();
            println!(
                "Mnemonic: {}\nPrivate Key: {}\nCCID: {}",
                entity.0, entity.1, entity.2
            );
        }
        SubCommand::VanitySearch {
            match_method,
            threads,
        } => {
            vanity_search(match_method, threads);
        }
        SubCommand::PhraseToCcid { mnemonic } => {
            println!("{}", phrase_to_ccid_str(&mnemonic));
        }
        SubCommand::PhraseToPrivkey { mnemonic } => {
            println!("{}", phrase_to_privkey_str(&mnemonic));
        }
        SubCommand::PhraseToPubkey { mnemonic } => {
            println!("{}", phrase_to_pubkey_str(&mnemonic));
        }
        SubCommand::PrivkeyToCcid { privkey } => {
            println!("{}", privkey_to_ccid_str(&privkey));
        }
        SubCommand::PrivkeyToPubkey { privkey } => {
            println!("{}", privkey_to_pubkey_str(&privkey));
        }
        SubCommand::PubkeyToCcid { pubkey } => {
            println!("{}", pubkey_to_ccid_str(&pubkey));
        }
    }
}
