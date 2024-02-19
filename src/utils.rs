use alloy_primitives::{keccak256, Address};
use coins_bip39::{mnemonic::Mnemonic, English, Wordlist};
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::fmt::Write;
use std::str::FromStr;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

pub fn mnemonic_to_addr<W: Wordlist>(mnemonic: &Mnemonic<W>) -> Address {
    privkey_to_addr(mnemonic_to_privkey(mnemonic))
}

pub fn mnemonic_to_privkey<W: Wordlist>(mnemonic: &Mnemonic<W>) -> SigningKey {
    let priv_key = mnemonic.derive_key(DEFAULT_DERIVATION_PATH, None).unwrap();
    let key: &coins_bip32::prelude::SigningKey = priv_key.as_ref();
    SigningKey::from_bytes(&key.to_bytes()).unwrap()
}

pub fn privkey_to_addr(privkey: SigningKey) -> Address {
    pubkey_to_addr(&privkey_to_pubkey(privkey))
}

pub fn privkey_to_pubkey(privkey: SigningKey) -> Vec<u8> {
    privkey.verifying_key().to_sec1_bytes().to_vec()
}

pub fn pubkey_to_addr(pubkey: &[u8]) -> Address {
    let pubkey = VerifyingKey::from_sec1_bytes(pubkey)
        .unwrap()
        .as_ref()
        .to_encoded_point(false);
    Address::from_slice(&keccak256(&pubkey.as_bytes()[1..])[12..])
}

pub fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{:02x}", b);
        output
    })
}

pub fn start_with_cc(text: &str) -> bool {
    text.to_uppercase().starts_with("CC")
}

pub fn is_hex(text: &str) -> bool {
    text.to_uppercase().chars().all(|c| c.is_ascii_hexdigit())
}

pub fn phrase_to_ccid_str(mnemonic: &str) -> String {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic).unwrap();
    mnemonic_to_addr(&mnemonic).to_string().replace("0x", "CC")
}

pub fn phrase_to_privkey_str(mnemonic: &str) -> String {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic).unwrap();
    hex_encode(mnemonic_to_privkey(&mnemonic).to_bytes().as_ref())
}

pub fn phrase_to_pubkey_str(mnemonic: &str) -> String {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic).unwrap();
    let privkey = mnemonic_to_privkey(&mnemonic);
    hex_encode(&privkey_to_pubkey(privkey))
}

pub fn privkey_to_ccid_str(privkey: &str) -> String {
    let key = SigningKey::from_slice(&hex_decode(privkey)).unwrap();
    let addr = privkey_to_addr(key);
    addr.to_string().replace("0x", "CC")
}

pub fn privkey_to_pubkey_str(privkey: &str) -> String {
    let key = SigningKey::from_slice(&hex_decode(privkey)).unwrap();
    hex_encode(&privkey_to_pubkey(key))
}

pub fn pubkey_to_ccid_str(pubkey: &str) -> String {
    let addr = pubkey_to_addr(&hex_decode(pubkey));
    addr.to_string().replace("0x", "CC")
}

pub fn generate_ccid<T: Wordlist>() -> (String, String, String) {
    let mnemonic: Mnemonic<T> = Mnemonic::new(&mut rand::thread_rng());
    let mnemonic = mnemonic.to_phrase();
    let privkey = phrase_to_privkey_str(&mnemonic);
    let ccid = phrase_to_ccid_str(&mnemonic);
    (mnemonic, privkey, ccid)
}
