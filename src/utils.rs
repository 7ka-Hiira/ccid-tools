use alloy_primitives::keccak256;
use alloy_primitives::Address;
use coins_bip39::mnemonic::Mnemonic;
use coins_bip39::Wordlist;
use k256::ecdsa::SigningKey;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

pub fn mnemonic2addr<W: Wordlist>(mnemonic: &Mnemonic<W>) -> Address {
    privkey2addr(mnemonic2privkey(mnemonic))
}

pub fn mnemonic2privkey<W: Wordlist>(mnemonic: &Mnemonic<W>) -> SigningKey {
    let priv_key = mnemonic.derive_key(DEFAULT_DERIVATION_PATH, None).unwrap();
    let key: &coins_bip32::prelude::SigningKey = priv_key.as_ref();
    SigningKey::from_bytes(&key.to_bytes()).unwrap()
}

pub fn privkey2addr(privkey: SigningKey) -> Address {
    pubkey2addr(&privkey2pubkey(privkey))
}

pub fn privkey2pubkey(privkey: SigningKey) -> Vec<u8> {
    //let key = SigningKey::from_slice(privkey).unwrap();
    privkey.verifying_key().to_sec1_bytes().to_vec()
}

pub fn pubkey2addr(pubkey: &[u8]) -> Address {
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
