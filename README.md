# CCID Tools

Tools for working with CCID (used in [concurrent](https://github.com/totegamma/concurrent))

## Installation

1. Download binary from [Releases](https://github.com/7ka-Hiira/ccid-tools/releases/latest)
2. Grant Permission (Linux)
```
$ cd /path/to/your/download/directory
$ mv <downloaded filename> ccid-tools
$ chmod +x ./ccid-tools
```
3. Run
```
$ ./ccid-tools <subcommand> <options>
```

- Tips: Building and optimizing on your CPU may improve speed
```
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

## Usage

### Generate an entity
```
$ ./ccidd-tools keygen
```

### Vanity key generation
You'll get Mnemonics and Addresses

Examples

- Generate CCID starts with 12345 and Japanese mnemonic
```
$ ./ccid-tools vanity-search --starts-with 12345 --lang ja
```

- Generate CCID containing abcdef (case-sensitive) with 3 threads, stop when one is found
```
$ ./ccid-tools vanity-search --contains abcdef -j3 --stop-when-found --case-sensitive
```

- Generate CCID where the 10 characters following the CC and the last 10 characters are numbers
```
$ ./ccid-tools vanity-search --regex "^CC\d{10}.*\d{10}$"
```

### Key derivation

Examples

- Derive privatekey from mnemonics
```
$ ./ccid-tools phrase-to-privkey "return velvet service basket ..."
```
- Derive CCID from privatekey
```
$ ./ccid-tools privkey-to-ccid "bcb7710a8cb369bc695e7e200611d501b..."
```

## Contributing

New features, bug reports/fixes, and improvements are welcome:)

## License

Apache 2.0

## Thanks

- [Alloy](https://github.com/alloy-rs/alloy/)
- [coins](https://github.com/summa-tx/coins)
- [num_cpus](https://github.com/seanmonstar/num_cpus)
- [Rand](https://github.com/rust-random/rand)
- [Rust](https://github.com/rust-lang)

And lots of related stuff!
