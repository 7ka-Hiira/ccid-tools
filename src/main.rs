pub mod utils;
mod vanity;

use clap::{Parser, Subcommand, ValueEnum};
use coins_bip39::{
    ChineseSimplified, ChineseTraditional, Czech, English, French, Italian, Japanese, Korean,
    Portuguese, Spanish, Wordlist,
};
use utils::{
    generate_entity, mnemonic_to_address_str, mnemonic_to_privkey_str, mnemonic_to_pubkey_str,
    privkey_to_address_str, privkey_to_pubkey_str, pubkey_to_address_str, translate_mnemonic,
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

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub enum MnemonicLang {
    #[value(alias("chinese_simplified"), alias("chinesesimplified"), alias("ChineseSimplified"))]
    #[value(alias("simplified_chinese"), alias("simplifiedchinese"), alias("SimplifiedChinese"))]
    #[value(alias("zh-cn"), alias("cn"))]
    #[value(alias("中文"), alias("简体中文"), alias("简体"))]
    ZhHans,
    #[value(alias("chinese_traditional"), alias("chinesetraditional"), alias("ChineseTraditional"))]
    #[value(alias("traditional_chinese"), alias("traditionalchinese"), alias("TraditionalChinese"))]
    #[value(alias("zh-tw"), alias("tw"), alias("zh-hk"))]
    #[value(alias("繁體中文"), alias("繁體"))]
    ZhHant,
    #[value(alias("czech"), alias("Czech"))]
    #[value(alias("cesky jazyk"), alias("český jazyk"))]
    Cs,
    #[value(alias("english"), alias("English"))]
    En,
    #[value(alias("french"), alias("French"))]
    #[value(alias("francais"), alias("Francais"), alias("français"), alias("Français"))]
    Fr,
    #[value(alias("italian"), alias("Italian"))]
    #[value(alias("italiano"), alias("Italiano"))]
    It,
    #[value(alias("japanese"), alias("Japanese"))]
    #[value(alias("日本語"), alias("にほんご"))]
    Ja,
    #[value(alias("korean"), alias("Korean"))]
    #[value(alias("한국어"))]
    Ko,
    #[value(alias("portuguese"), alias("Portuguese"))]
    #[value(alias("portugalština"), alias("Portugalština"))]
    Pt,
    #[value(alias("spanish"), alias("Spanish"))]
    #[value(alias("espanol"), alias("Espanol"), alias("español"), alias("Español"))]
    Es,
}

impl MnemonicLang {
    fn to_words(self) -> &'static [&'static str] {
        match self {
            MnemonicLang::ZhHans => ChineseSimplified::get_all(),
            MnemonicLang::ZhHant => ChineseTraditional::get_all(),
            MnemonicLang::Cs => Czech::get_all(),
            MnemonicLang::En => English::get_all(),
            MnemonicLang::Fr => French::get_all(),
            MnemonicLang::It => Italian::get_all(),
            MnemonicLang::Ja => Japanese::get_all(),
            MnemonicLang::Ko => Korean::get_all(),
            MnemonicLang::Pt => Portuguese::get_all(),
            MnemonicLang::Es => Spanish::get_all(),
        }
    }
    fn get_index(self, word: &str) -> Result<usize, usize> {
        self.to_words().binary_search(&word)
    }
    fn get_lang_list() -> [Self; 10] {
        [
            MnemonicLang::ZhHans,
            MnemonicLang::ZhHant,
            MnemonicLang::Cs,
            MnemonicLang::En,
            MnemonicLang::Fr,
            MnemonicLang::It,
            MnemonicLang::Ja,
            MnemonicLang::Ko,
            MnemonicLang::Pt,
            MnemonicLang::Es,
        ]
    }
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

impl MatchMethodStruct {
    fn into_matchmethod(self) -> MatchMethod {
        match self {
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
        }
    }
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
            let entity = generate_entity::<coins_bip39::English>(lang).unwrap_or_else(|e| {
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
            let match_method = match_method.into_matchmethod();
            vanity::lookup(match_method, threads, stop_when_found, case_sensitive, lang);
        }
        SubCommand::MnemonicToAddress { mnemonic } => {
            let mnemonic = translate_mnemonic(&mnemonic, MnemonicLang::En);
            println!(
                "{}",
                mnemonic_to_address_str(&mnemonic).unwrap_or_else(|e| {
                    panic!("Failed to derive CCID from mnemonic: {e}");
                })
            );
        }
        SubCommand::MnemonicToPrivkey { mnemonic } => {
            let mnemonic = translate_mnemonic(&mnemonic, MnemonicLang::En);
            println!(
                "{}",
                mnemonic_to_privkey_str(&mnemonic).unwrap_or_else(|e| {
                    panic!("Failed to derive private key from mnemonic: {e}");
                })
            );
        }
        SubCommand::MnemonicToPubkey { mnemonic } => {
            let mnemonic = translate_mnemonic(&mnemonic, MnemonicLang::En);
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
            let result = translate_mnemonic(&mnemonic, target_lang);
            println!("{result}");
        }
    }
}
