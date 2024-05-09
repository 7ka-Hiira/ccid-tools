use bech32::{Bech32, Hrp};
use coins_bip32::prelude::SigningKey as Bip32SigningKey;
use coins_bip39::{mnemonic::Mnemonic, English, Wordlist};
use core::str::FromStr;
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use ripemd::{Digest, Ripemd160};
use std::error::Error;
use unicode_normalization::UnicodeNormalization;

use crate::MnemonicLang;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/118'/0'/0/0";
const CC_HRP: Hrp = Hrp::parse_unchecked("con");

#[inline]
pub fn translate_mnemonic(
    mnemonic: &str,
    target_lang: MnemonicLang,
) -> Result<String, Box<dyn Error>> {
    let source_lang = detect_mnemonic_lang(mnemonic)?;
    if source_lang == target_lang {
        return Ok(mnemonic.to_string());
    }
    Ok(mnemonic
        .split_whitespace()
        .map(|word| {
            let index = source_lang
                .get_index(&word.nfkd().collect::<String>())
                .unwrap_or_else(|e| panic!("failded to parse mnemonic word: {e}"));
            target_lang.to_words()[index].to_owned()
        })
        .collect::<Vec<String>>()
        .join(" "))
}

#[inline]
fn detect_mnemonic_lang(mnemonic: &str) -> Result<MnemonicLang, Box<dyn Error>> {
    MnemonicLang::get_lang_list()
        .iter()
        .find(|lang| {
            let words = lang.to_words();
            mnemonic
                .split_whitespace()
                .all(|word| words.contains(&word))
        })
        .copied()
        .ok_or("Failed to detect mnemonic language".into())
}

#[inline]
pub fn mnemonic_to_addr<W: Wordlist>(mnemonic: &Mnemonic<W>) -> Result<String, Box<dyn Error>> {
    privkey_to_addr(&mnemonic_to_privkey(mnemonic)?)
}

#[inline]
pub fn mnemonic_to_privkey<W: Wordlist>(
    mnemonic: &Mnemonic<W>,
) -> Result<SigningKey, Box<dyn Error>> {
    let priv_key = mnemonic.derive_key(DEFAULT_DERIVATION_PATH, None)?;
    let key: &Bip32SigningKey = priv_key.as_ref();
    Ok(SigningKey::from_bytes(&key.to_bytes())?)
}

#[inline]
pub fn privkey_to_addr(privkey: &SigningKey) -> Result<String, Box<dyn Error>> {
    pubkey_to_addr(&privkey_to_pubkey(privkey))
}

#[inline]
pub fn privkey_to_pubkey(privkey: &SigningKey) -> Vec<u8> {
    privkey.verifying_key().to_sec1_bytes().to_vec()
}

#[inline]
pub fn pubkey_to_addr(pubkey: &[u8]) -> Result<String, Box<dyn Error>> {
    let pubkey = VerifyingKey::from_sec1_bytes(pubkey)?
        .as_ref()
        .to_encoded_point(false);
    let pubkey = secp256k1::PublicKey::from_slice(pubkey.as_bytes())?.serialize();
    let mut sha256hasher = sha2::Sha256::new();
    sha256hasher.update(pubkey);
    let pubkey = Ripemd160::digest(sha256hasher.finalize());
    let pubkey = bech32::encode::<Bech32>(CC_HRP, &pubkey)?;
    Ok(pubkey.to_string())
}

#[inline]
pub fn mnemonic_to_address_str(mnemonic_en: &str) -> Result<String, Box<dyn Error>> {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic_en)?;
    Ok(mnemonic_to_addr(&mnemonic)?.to_string())
}

#[inline]
pub fn mnemonic_to_privkey_str(mnemonic_en: &str) -> Result<String, Box<dyn Error>> {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic_en)?;
    Ok(hex::encode(mnemonic_to_privkey(&mnemonic)?.to_bytes()))
}

#[inline]
pub fn mnemonic_to_pubkey_str(mnemonic_en: &str) -> Result<String, Box<dyn Error>> {
    let mnemonic: Mnemonic<English> = Mnemonic::from_str(mnemonic_en)?;
    let privkey = mnemonic_to_privkey(&mnemonic)?;
    Ok(hex::encode(privkey_to_pubkey(&privkey)))
}

#[inline]
pub fn privkey_to_address_str(privkey: &str, is_subkey: bool) -> Result<String, Box<dyn Error>> {
    let key = SigningKey::from_slice(&hex::decode(privkey)?)?;
    let addr = privkey_to_addr(&key);
    if is_subkey {
        Ok(addr?.to_string().replacen("con", "cck", 1))
    } else {
        Ok(addr?.to_string())
    }
}

#[inline]
pub fn privkey_to_pubkey_str(privkey: &str) -> Result<String, Box<dyn Error>> {
    let key = SigningKey::from_slice(&hex::decode(privkey)?)?;
    Ok(hex::encode(privkey_to_pubkey(&key)))
}

#[inline]
pub fn pubkey_to_address_str(pubkey: &str, is_subkey: bool) -> Result<String, Box<dyn Error>> {
    let addr = pubkey_to_addr(&hex::decode(pubkey)?);
    if is_subkey {
        Ok(addr?.to_string().replacen("con", "cck", 1))
    } else {
        Ok(addr?.to_string())
    }
}

#[inline]
pub fn generate_entity(lang: MnemonicLang) -> Result<(String, String, String), Box<dyn Error>> {
    let mnemonic = Mnemonic::<English>::new(&mut ChaCha20Rng::from_entropy()).to_phrase();
    let privkey = mnemonic_to_privkey_str(&mnemonic)?;
    let ccid = mnemonic_to_address_str(&mnemonic)?;
    let mnemonic = translate_mnemonic(&mnemonic, lang)?;
    Ok((mnemonic, privkey, ccid))
}

#[inline]
pub fn mnemonic_to_addr_fast<W: Wordlist>(
    mnemonic: &Mnemonic<W>,
) -> Result<String, Box<dyn Error>> {
    let privkey = mnemonic.derive_key(DEFAULT_DERIVATION_PATH, None)?;
    let privkey: &Bip32SigningKey = privkey.as_ref();
    let pubkey = secp256k1::PublicKey::from_slice(
        SigningKey::from_bytes(&privkey.to_bytes())?
            .verifying_key()
            .as_ref()
            .to_encoded_point(false)
            .as_bytes(),
    )?
    .serialize();
    let mut sha256hasher = sha2::Sha256::new();
    sha256hasher.update(pubkey);
    let pubkey = bech32::encode::<Bech32>(CC_HRP, &Ripemd160::digest(sha256hasher.finalize()))?;
    Ok(pubkey.to_string())
}

#[cfg(test)]
mod tests {

    use super::*;

    // test wallet
    const MNEMONIC_EN_STR: &str =
        "maximum talk hill differ mouse happy practice rocket earth theme manual match";
    const MNEMONIC_JA_STR: &str = "たこやき ほしつ しょっけん くなん たんてい しゃけん とない ねんど けとばす まかい たいやき たかい";
    const PRIVKEY: &str = "aa9063661ab20513c65c39f80575fa2306e51a45c2c51e57ab485771fd4b8d1a";
    const PUBKEY: &str = "033baddf65aabd9e341976d9cade07d24382857195bbe20c3ee826a041420535ba";
    const ADDRESS: &str = "con1test0zagl292e2xdnzfy2u6ggr46rm7k3a06p7";

    #[test]
    fn test_translate_mnemonic() {
        let translated = translate_mnemonic(MNEMONIC_EN_STR, MnemonicLang::Ja).unwrap();
        assert_eq!(translated, MNEMONIC_JA_STR);
    }

    #[test]
    fn test_detect_mnemonic_lang() {
        let lang = detect_mnemonic_lang(MNEMONIC_EN_STR).unwrap();
        assert!(lang == MnemonicLang::En);
        let lang = detect_mnemonic_lang(MNEMONIC_JA_STR).unwrap();
        assert!(lang == MnemonicLang::Ja);
    }

    #[test]
    fn test_mnemonic_to_address_str() {
        let address = mnemonic_to_address_str(MNEMONIC_EN_STR).unwrap();
        assert_eq!(address, ADDRESS);
    }

    #[test]
    fn test_mnemonic_to_privkey_str() {
        let privkey = mnemonic_to_privkey_str(MNEMONIC_EN_STR).unwrap();
        assert_eq!(privkey, PRIVKEY);
    }

    #[test]
    fn test_mnemonic_to_pubkey_str() {
        let pubkey = mnemonic_to_pubkey_str(MNEMONIC_EN_STR).unwrap();
        assert_eq!(pubkey, PUBKEY);
    }

    #[test]
    fn test_privkey_to_address_str() {
        let address = privkey_to_address_str(PRIVKEY, false).unwrap();
        assert_eq!(address, ADDRESS);
    }

    #[test]
    fn test_privkey_to_pubkey_str() {
        let pubkey = privkey_to_pubkey_str(PRIVKEY).unwrap();
        assert_eq!(pubkey, PUBKEY);
    }

    #[test]
    fn test_pubkey_to_address_str() {
        let address = pubkey_to_address_str(PUBKEY, false).unwrap();
        assert_eq!(address, ADDRESS);
    }

    #[test]
    fn test_generate_entity() {
        let (mnemonic, privkey, address) = generate_entity(MnemonicLang::En).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 12);
        assert!(address.starts_with("con1"));
        assert_eq!(privkey.len(), 64);
        assert_eq!(address.len(), 42);
    }

    #[test]
    fn test_mnemonic_to_addr_fast() {
        let mnemonic: Mnemonic<English> = Mnemonic::from_str(MNEMONIC_EN_STR).unwrap();
        let address = mnemonic_to_addr_fast(&mnemonic).unwrap();
        assert_eq!(address, ADDRESS);
    }
}
