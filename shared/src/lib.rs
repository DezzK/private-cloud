pub mod consts;
pub mod hasher;

use anyhow::{anyhow, bail, Result};
use borsh::io::Write;
use borsh::BorshSerialize;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::ops::Deref;
use std::time::SystemTime;

#[derive(Debug)]
pub struct SignableRequest {
    filename: String,
    pubkey: VerifyingKey,
    time: u64,
}

#[derive(Debug)]
pub struct SignedRequest {
    request: SignableRequest,
    signature: Signature,
}

const MAX_CLIENT_TIME_DIFF: u64 = 60;

impl SignableRequest {
    pub fn with_time(filename: String, pubkey: VerifyingKey, time: u64) -> Self {
        Self {
            filename,
            pubkey,
            time,
        }
    }

    pub fn new(filename: String, pubkey: VerifyingKey) -> Result<Self> {
        Ok(Self::with_time(filename, pubkey, Self::unix_time()?))
    }

    pub fn filename(&self) -> &str {
        &self.filename
    }

    pub fn pubkey(&self) -> &VerifyingKey {
        &self.pubkey
    }

    pub fn time(&self) -> u64 {
        self.time
    }

    pub fn sign(self, secret: &SigningKey) -> Result<SignedRequest> {
        let msg = self.serialize_borsh()?;
        let signature = secret.try_sign(&msg)?;

        Ok(SignedRequest {
            request: self,
            signature,
        })
    }

    pub fn check_signature(&self, request_signature: &Signature) -> Result<()> {
        let unix_time = Self::unix_time()?;
        let time_diff = unix_time.abs_diff(self.time);
        if time_diff > MAX_CLIENT_TIME_DIFF {
            bail!("Time difference is too high ({time_diff} seconds). Client's and server's clocks must be synchronized.");
        }

        let msg = self.serialize_borsh()?;
        self.pubkey.verify_strict(&msg, request_signature)?;

        Ok(())
    }

    fn unix_time() -> Result<u64> {
        Ok(SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs())?)
    }

    fn serialize_borsh(&self) -> Result<Vec<u8>> {
        borsh::to_vec(self).map_err(|err| anyhow!(err))
    }
}

impl BorshSerialize for SignableRequest {
    fn serialize<W: Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let Self {
            filename,
            pubkey,
            time,
        } = self;

        filename.serialize(writer)?;
        pubkey.as_bytes().serialize(writer)?;
        time.serialize(writer)
    }
}

impl SignedRequest {
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

impl Deref for SignedRequest {
    type Target = SignableRequest;

    fn deref(&self) -> &Self::Target {
        &self.request
    }
}
