# [WIP] CCID Tools

Tools for working with CCID (used in https://github.com/totegamma/concurrent)

## Installation

1. Download binary from [Releases](https://github.com/7ka-Hiira/ccid-tools/releases/latest)
2. Grant Permission (Linux)
```
$ cd /path/to/your/download/directory
$ chmod +x ./ccid-tools
```
3. Run
```
$ ./ccid-tools <subcommand> <options>
```

## Usage

### Vanity key generation
You'll get Mnemonics and Addresses.

Examples

- Generate CCID start with CC1234
```
$ ccid-tools vanity --start-with cc1234
```

- Generate CCID containing abcd with 3 threads
```
$ ccid-tools vanity --contains abcd -j 3
```

- Generate CCID where the 10 characters following the CC and the last 10 characters are numbers.
```
$ ccid-tools vanity --regex "^CC\d{10}.*\d{10}$"
```

## Contributing

New features, bug reports/fixes, and improvements to this terrible code are welcome.

## License

Apache 2.0

## Thanks

- [Alloy](https://github.com/alloy-rs/alloy/)
- [coins](https://github.com/summa-tx/coins)
- [num_cpus](https://github.com/seanmonstar/num_cpus)
- [Rand](https://github.com/rust-random/rand)
- [Rust](https://github.com/rust-lang)

And lots of related stuff!