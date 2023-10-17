use std::env::temp_dir;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use log::info;
use once_cell::sync::Lazy;
use rand::RngCore;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;

use crate::CONFIG;

const TEMP_PREFIX: &str = "cloud-uploading";

static TEMP_DIR: Lazy<PathBuf> = Lazy::new(temp_dir);

#[derive(Debug)]
pub struct FileWriter {
    temp_file: Option<(File, PathBuf)>,
}

impl FileWriter {
    pub async fn new() -> std::io::Result<Self> {
        let (temp_file, temp_filename) = loop {
            let number = rand::thread_rng().next_u32();
            let filename = TEMP_DIR.join(format!("{}-{}.tmp", TEMP_PREFIX, number));
            match File::options()
                .create_new(true)
                .write(true)
                .open(&filename)
                .await
            {
                Ok(file) => break (file, filename),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err),
            }
        };

        Ok(Self {
            temp_file: Some((temp_file, temp_filename)),
        })
    }

    pub async fn append_chunk(&mut self, data: &[u8]) -> std::io::Result<()> {
        match &mut self.temp_file {
            Some((temp_file, _temp_filename)) => temp_file.write_all(data).await,
            None => Err(ErrorKind::NotFound.into()),
        }
    }

    pub async fn finalize(
        mut self,
        filename: &str,
        pubkey: &VerifyingKey,
        signature: &Signature,
    ) -> Result<()> {
        if let Some((temp_file, temp_filename)) = self.temp_file.take() {
            temp_file.sync_all().await?;
            let (file_path, signature_path) =
                get_file_paths(&CONFIG.storage_path, pubkey, filename).await?;
            tokio::fs::create_dir_all(
                file_path
                    .parent()
                    .ok_or(anyhow!("Unable to get parent directory"))?,
            )
            .await?;
            tokio::fs::write(signature_path, signature.to_vec()).await?;
            tokio::fs::rename(temp_filename, &file_path).await?;
            info!("File written to: {file_path:?}");
        }
        Ok(())
    }

    pub async fn drop_temp_file(mut self) -> std::io::Result<()> {
        if let Some((_temp_file, temp_filename)) = self.temp_file.take() {
            tokio::fs::remove_file(temp_filename).await?;
        }
        Ok(())
    }
}

impl Drop for FileWriter {
    fn drop(&mut self) {
        if let Some((_temp_file, temp_filename)) = self.temp_file.take() {
            std::fs::remove_file(temp_filename).ok();
        }
    }
}

pub async fn get_file_paths(
    storage_path: impl AsRef<Path>,
    pubkey: &VerifyingKey,
    filename: &str,
) -> Result<(PathBuf, PathBuf)> {
    let pubkey = bs58::encode(pubkey.as_bytes()).into_string();
    let path = storage_path.as_ref().join(pubkey).join(filename);
    if !path.starts_with(storage_path.as_ref()) {
        bail!("Trying to get path outside storage directory")
    }
    let signature_path = path.with_extension("sig");
    Ok((path, signature_path))
}
