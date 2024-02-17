use alloy_primitives::Address;
use alloy_signer::coins_bip39::mnemonic::Mnemonic;
use alloy_signer::coins_bip39::Wordlist;
use alloy_signer::k256::ecdsa::SigningKey;
use alloy_signer::utils::secret_key_to_address;

const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

pub fn mnemonic2addr<W: Wordlist>(mnemonic: &Mnemonic<W>) -> Address {
    secret_key_to_address(&mnemonic2privkey(mnemonic))
}

pub fn mnemonic2privkey<W: Wordlist>(mnemonic: &Mnemonic<W>) -> SigningKey {
    let priv_key = mnemonic.derive_key(DEFAULT_DERIVATION_PATH, None).unwrap();
    let key: &coins_bip32::prelude::SigningKey = priv_key.as_ref();
    SigningKey::from_bytes(&key.to_bytes()).unwrap()
}
