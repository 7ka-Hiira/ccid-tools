use clap::{Parser, Subcommand};
use std::thread;

mod vanity;
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
    Vanity {
        #[clap(flatten)]
        match_method: MatchMethod,
        /// Number of threads to use
        #[clap(short = 'j', long, value_name = "THREAD_NUM")]
        threads: Option<usize>,
    },
}

fn main() {
    let args: Arg = Arg::parse();
    match args.subcommand {
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
                    panic!("CCID must start with 'CC'")
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
            let mut threads_num = threads.unwrap_or(num_cpus::get()) - 1;
            if threads_num <= 0 {
                threads_num = num_cpus::get() - 1;
            }
            for _ in 0..threads_num {
                let m = method.clone();
                thread::spawn(move || {
                    find_ccid_from_mnemonic(m);
                });
            }
            find_ccid_from_mnemonic(method);
        }
    }
}
