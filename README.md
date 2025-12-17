# CCID Tools

A [Concurrent](https://github.com/totegamma/concurrent) CCID Management Tool.

## Installation (Linux)

1. Download the binary from [Releases](https://github.com/7ka-Hiira/ccid-tools/releases/latest)
2. Grant permission:

```sh
$ cd /path/to/your/download/directory
$ mv <downloaded filename> ccid-tools
$ chmod +x ./ccid-tools
```

3. Run

```sh
$ ./ccid-tools <subcommand> <options>
```

## Build from source

You may need to build it yourself, as the official build does not work on some older CPUs.

```sh
$ git clone https://github.com/7ka-Hiira/ccid-tools.git
$ cd ccid-tools
$ RUSTFLAGS="-C target-cpu=native" cargo build --release
```

You can find the binary in `./target/release/ccid-tools`

## Usage

### Generate an Entity

```sh
$ ./ccid-tools keygen
```

### Vanity Key Generation

You can get mnemonics and addresses

#### Examples

- Generate CCIDs starting with con12345 and using a Japanese mnemonic

```sh
$ ./ccid-tools vanity-search --starts-with 2345 --lang ja
```

- Generate a CCID containing 'xyz' using 3 threads, stopping when one is found

```sh
$ ./ccid-tools vanity-search --contains xyz -j3 --stop-when-found
```

- Generate CCIDs where the 5 characters after 'con1' and the last 5 characters are numbers

```sh
$ ./ccid-tools vanity-search --regex "^con1\d{5}.*\d{5}$"
```

### Key derivation

#### Examples

- Derive a privatekey from mnemonics

```sh
$ ./ccid-tools mnemonic-to-privkey "return velvet service basket ..."
```

- Derive a CCID from privatekey

```sh
$ ./ccid-tools privkey-to-address "bcb7710a8cb369bc695e7e200611d501b..."
```

## Contributing

New features, bug reports/fixes, and improvements are welcome! :)

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
