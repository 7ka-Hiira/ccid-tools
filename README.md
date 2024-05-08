# CCID Tools

A [Concurrent](https://github.com/totegamma/concurrent) CCID management tool.

## Installation (Linux)

1. Download binary from [Releases](https://github.com/7ka-Hiira/ccid-tools/releases/latest)
2. Grant Permission

```sh
$ cd /path/to/your/download/directory
$ mv <downloaded filename> ccid-tools
$ chmod +x ./ccid-tools
```

3. Run

```sh
$ ./ccid-tools <subcommand> <options>
```

## Build yourself
official build doesn't work on some old CPUs, so you may need to build it yourself.
```sh
$ git clone https://github.com/7ka-Hiira/ccid-tools.git
$ cd ccid-tools
$ RUSTFLAGS="-C target-cpu=native" cargo build --release
```
You can find the binary in `./target/release/ccid-tools`


## Usage

### Generate an entity

```sh
$ ./ccid-tools keygen
```

### Vanity key generation

You'll get Mnemonics and Addresses

Examples

- Generate CCID starts with 12345 and Japanese mnemonic

```sh
$ ./ccid-tools vanity-search --starts-with 2345 --lang ja
```

- Generate CCID containing abcdef (case-sensitive) with 3 threads, stop when one is found

```sh
$ ./ccid-tools vanity-search --contains xyz -j3 --stop-when-found --case-sensitive
```

- Generate CCID where the 5 characters following the 'con1' and the last 5 characters are numbers

```sh
$ ./ccid-tools vanity-search --regex "^con1\d{5}.*\d{5}$"
```

### Key derivation

Examples

- Derive privatekey from mnemonics

```sh
$ ./ccid-tools mnemonic-to-privkey "return velvet service basket ..."
```

- Derive CCID from privatekey

```sh
$ ./ccid-tools privkey-to-address "bcb7710a8cb369bc695e7e200611d501b..."
```

## Contributing

New features, bug reports/fixes, and improvements are welcome:)

## License

Apache 2.0

## Acknowledgements

[clap](https://github.com/clap-rs/clap)
[coins](https://github.com/summa-tx/coins)
[concurrent-client](https://github.com/totegamma/concurrent-client)
[elliptic-curves](https://github.com/RustCrypto/elliptic-curves)
[num_cpus](https://github.com/seanmonstar/num_cpus)
[rand](https://github.com/rust-random/rand)
[regex](https://github.com/rust-lang/regex)
[RustCrypto: Hashes](https://github.com/RustCrypto/hashes)
[rust-bech32](https://github.com/rust-bitcoin/rust-bech32)
[rust-hex](https://github.com/KokaKiwi/rust-hex)
[rust-secp256k1](https://github.com/rust-bitcoin/rust-secp256k1)
[unicode-normalization](https://github.com/unicode-rs/unicode-normalization)
