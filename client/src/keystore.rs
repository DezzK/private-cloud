use anyhow::Result;
use ed25519_dalek::{SecretKey, SigningKey};
use keyring::{Entry, Error};
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub trait KeyStore {
    fn regenerate_keypair(&self) -> Result<()>;
    fn get_signing_key(&self) -> Result<SigningKey>;
}

const SERVICE_NAME: &str = "cloud-cli";
const USER_NAME: &str = "secret";

pub struct Keyring;

impl KeyStore for Keyring {
    fn regenerate_keypair(&self) -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, USER_NAME)?;
        if let Err(err) = entry.delete_password() {
            if !matches!(err, Error::NoEntry) {
                Err(err)?;
            }
        }

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let mut secret = signing_key.to_bytes();
        let mut secret_base58 = bs58::encode(&secret).into_string();
        secret.zeroize();

        let result = entry.set_password(&secret_base58);

        secret_base58.zeroize();

        Ok(result?)
    }

    fn get_signing_key(&self) -> Result<SigningKey> {
        let entry = Entry::new(SERVICE_NAME, USER_NAME)?;
        let mut secret_base58 = entry.get_password()?;

        let result = bs58::decode(&secret_base58).into_vec();
        secret_base58.zeroize();

        let mut secret = match result {
            Ok(secret) => secret,
            Err(err) => Err(err)?,
        };

        let result: std::result::Result<SecretKey, _> = secret.as_slice().try_into();
        secret.zeroize();

        let mut secret_key = match result {
            Ok(secret_key) => secret_key,
            Err(err) => Err(err)?,
        };

        let signing_key = SigningKey::from_bytes(&secret_key);
        secret_key.zeroize();

        Ok(signing_key)
    }
}
