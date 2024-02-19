use alloy_primitives::{keccak256, Address};
use coins_bip39::{mnemonic::Mnemonic, English, Japanese, Wordlist};
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::str::FromStr;
use unicode_normalization::UnicodeNormalization;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

pub fn ja_mnemonic_to_en(mnemonic: &str) -> String {
    mnemonic
        .split_whitespace()
        .map(|word| Japanese::get_index(&word.nfkd().collect::<String>()).unwrap())
        .map(|index| English::get(index).unwrap().to_owned())
        .collect::<Vec<String>>()
        .join(" ")
}

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
    hex::encode(mnemonic_to_privkey(&mnemonic).to_bytes())
}

pub fn phrase_to_pubkey_str(mnemonic: &str) -> String {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic).unwrap();
    let privkey = mnemonic_to_privkey(&mnemonic);
    hex::encode(privkey_to_pubkey(privkey))
}

pub fn privkey_to_ccid_str(privkey: &str) -> String {
    let key = SigningKey::from_slice(&hex::decode(privkey).unwrap()).unwrap();
    let addr = privkey_to_addr(key);
    addr.to_string().replace("0x", "CC")
}

pub fn privkey_to_pubkey_str(privkey: &str) -> String {
    let key = SigningKey::from_slice(&hex::decode(privkey).unwrap()).unwrap();
    hex::encode(privkey_to_pubkey(key))
}

pub fn pubkey_to_ccid_str(pubkey: &str) -> String {
    let addr = pubkey_to_addr(&hex::decode(pubkey).unwrap());
    addr.to_string().replace("0x", "CC")
}

pub fn generate_ccid<T: Wordlist>() -> (String, String, String) {
    let mnemonic: Mnemonic<T> = Mnemonic::new(&mut ChaCha20Rng::from_entropy());
    let mnemonic = mnemonic.to_phrase();
    let privkey = phrase_to_privkey_str(&mnemonic);
    let ccid = phrase_to_ccid_str(&mnemonic);
    (mnemonic, privkey, ccid)
}
