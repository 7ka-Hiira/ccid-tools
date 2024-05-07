use alloy_primitives::{keccak256, Address};
use coins_bip32::prelude::SigningKey as Bip32SigningKey;
use coins_bip39::{mnemonic::Mnemonic, English, Japanese, Wordlist};
use core::str::FromStr;
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::error::Error;
use unicode_normalization::UnicodeNormalization;

use crate::MnemonicLang;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

// ジェネリクス使えなさそう
pub fn ja_mnemonic_to_en(mnemonic: &str) -> String {
    mnemonic
        .split_whitespace()
        .map(|word| {
            Japanese::get_index(&word.nfkd().collect::<String>()).unwrap_or_else(|e| {
                panic!("Failed to parse Japanese mnemonic into English: {e}");
            })
        })
        .map(|index| English::get(index).unwrap().to_owned())
        .collect::<Vec<String>>()
        .join(" ")
}

pub fn en_mnemonic_to_ja(mnemonic: &str) -> String {
    mnemonic
        .split_whitespace()
        .map(|word| {
            English::get_index(&word.nfkd().collect::<String>()).unwrap_or_else(|e| {
                panic!("Failed to parse English mnemonic into Japanese: {e}");
            })
        })
        .map(|index| Japanese::get(index).unwrap().to_owned())
        .collect::<Vec<String>>()
        .join(" ")
}

pub fn detect_mnemonic_lang(mnemonic: &str) -> MnemonicLang {
    if mnemonic
        .split_whitespace()
        .all(|word| Japanese::get_index(&word.nfkd().collect::<String>()).is_ok())
    {
        crate::MnemonicLang::Ja
    } else if mnemonic
        .split_whitespace()
        .all(|word| English::get_index(&word.nfkd().collect::<String>()).is_ok())
    {
        MnemonicLang::En
    } else {
        panic!("Invalid mnemonic: {mnemonic}");
    }
}

pub fn mnemonic_to_addr<W: Wordlist>(mnemonic: &Mnemonic<W>) -> Result<Address, Box<dyn Error>> {
    privkey_to_addr(&mnemonic_to_privkey(mnemonic)?)
}

pub fn mnemonic_to_privkey<W: Wordlist>(
    mnemonic: &Mnemonic<W>,
) -> Result<SigningKey, Box<dyn Error>> {
    let priv_key = mnemonic.derive_key(DEFAULT_DERIVATION_PATH, None)?;
    let key: &Bip32SigningKey = priv_key.as_ref();
    Ok(SigningKey::from_bytes(&key.to_bytes())?)
}

pub fn privkey_to_addr(privkey: &SigningKey) -> Result<Address, Box<dyn Error>> {
    pubkey_to_addr(&privkey_to_pubkey(privkey))
}

pub fn privkey_to_pubkey(privkey: &SigningKey) -> Vec<u8> {
    privkey.verifying_key().to_sec1_bytes().to_vec()
}

pub fn pubkey_to_addr(pubkey: &[u8]) -> Result<Address, Box<dyn Error>> {
    let pubkey = VerifyingKey::from_sec1_bytes(pubkey)?
        .as_ref()
        .to_encoded_point(false);
    Ok(Address::from_slice(
        &keccak256(&pubkey.as_bytes()[1..])[12..],
    ))
}

pub fn phrase_to_ccid_str(mnemonic: &str) -> Result<String, Box<dyn Error>> {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic)?;
    Ok(mnemonic_to_addr(&mnemonic)?.to_string().replace("0x", "CC"))
}

pub fn phrase_to_privkey_str(mnemonic: &str) -> Result<String, Box<dyn Error>> {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic)?;
    Ok(hex::encode(mnemonic_to_privkey(&mnemonic)?.to_bytes()))
}

pub fn phrase_to_pubkey_str(mnemonic: &str) -> Result<String, Box<dyn Error>> {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic)?;
    let privkey = mnemonic_to_privkey(&mnemonic)?;
    Ok(hex::encode(privkey_to_pubkey(&privkey)))
}

pub fn privkey_to_address_str(privkey: &str, is_subkey: bool) -> Result<String, Box<dyn Error>> {
    let key = SigningKey::from_slice(&hex::decode(privkey)?)?;
    let addr = privkey_to_addr(&key);
    if is_subkey {
        Ok(addr?.to_string().replace("0x", "CK"))
    } else {
        Ok(addr?.to_string().replace("0x", "CC"))
    }
}

pub fn privkey_to_pubkey_str(privkey: &str) -> Result<String, Box<dyn Error>> {
    let key = SigningKey::from_slice(&hex::decode(privkey)?)?;
    Ok(hex::encode(privkey_to_pubkey(&key)))
}

pub fn pubkey_to_address_str(pubkey: &str, is_subkey: bool) -> Result<String, Box<dyn Error>> {
    let addr = pubkey_to_addr(&hex::decode(pubkey)?);
    if is_subkey {
        Ok(addr?.to_string().replace("0x", "CK"))
    } else {
        Ok(addr?.to_string().replace("0x", "CC"))
    }
}

pub fn generate_entity<T: Wordlist>(
    lang: &crate::MnemonicLang,
) -> Result<(String, String, String), Box<dyn Error>> {
    let mnemonic = Mnemonic::<T>::new(&mut ChaCha20Rng::from_entropy()).to_phrase();
    let privkey = phrase_to_privkey_str(&mnemonic)?;
    let ccid = phrase_to_ccid_str(&mnemonic)?;
    let mnemonic = if matches!(lang, crate::MnemonicLang::Ja) {
        en_mnemonic_to_ja(&mnemonic)
    } else {
        mnemonic
    };
    Ok((mnemonic, privkey, ccid))
}
