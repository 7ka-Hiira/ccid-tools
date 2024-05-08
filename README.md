# CCID Tools

Tools for working with CCID (used in [concurrent](https://github.com/totegamma/concurrent))

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
$ ./ccid-tools vanity-search --starts-with 12345 --lang ja
```

- Generate CCID containing abcdef (case-sensitive) with 3 threads, stop when one is found

```sh
$ ./ccid-tools vanity-search --contains abcdef -j3 --stop-when-found --case-sensitive
```

- Generate CCID where the 10 characters following the 'con1' and the last 10 characters are numbers

```sh
$ ./ccid-tools vanity-search --regex "^con1\d{10}.*\d{10}$"
```

### Key derivation

Examples

- Derive privatekey from mnemonics

```sh
$ ./ccid-tools phrase-to-privkey "return velvet service basket ..."
```

- Derive CCID from privatekey

```sh
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
