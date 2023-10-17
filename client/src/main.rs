use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use clap::{arg, Command};
use ed25519_dalek::ed25519::signature::digest::Update;
use ed25519_dalek::DigestSigner;
use reqwest::Url;
use tempfile::NamedTempFile;

use shared::hasher::Hasher;
use shared::SignableRequest;

use crate::api::{Api, HttpClient};
use crate::keystore::{KeyStore, Keyring};

mod api;
mod keystore;

#[derive(serde::Deserialize)]
struct Config {
    pub server_url: Url,
    pub download_dir: PathBuf,
}

fn cli() -> Command {
    Command::new("cloud")
        .about("Private cloud CLI")
        .subcommand_required(true)
        .subcommand(
            Command::new("regenerate-keys")
                .about("Regenerate access keypair. Previous keypair will be lost!"),
        )
        .subcommand(
            Command::new("push")
                .about("Upload file to private cloud")
                .arg(arg!(<PATH> "Path of file to upload"))
                .arg_required_else_help(true),
        )
        .subcommand(
            Command::new("pull")
                .about("Download file from private cloud")
                .arg(arg!(<FILENAME> "Filename to download"))
                .arg_required_else_help(true),
        )
}

fn push(path: impl AsRef<Path>, keystore: impl KeyStore, api: impl Api) -> Result<()> {
    let mut file = File::open(&path)?;
    let filename = path
        .as_ref()
        .file_name()
        .ok_or(anyhow!("Filename not found in the path"))?
        .to_string_lossy();
    println!("File: {filename}, {} bytes", file.metadata()?.len(),);

    print!("Calculating signatures... ");
    std::io::stdout().flush().ok();

    let digest = calc_digest(&mut file)?;
    let signing_key = keystore.get_signing_key()?;
    let file_signature = signing_key.sign_digest(digest);

    let request = SignableRequest::new(filename.to_string(), signing_key.verifying_key())?;
    let request = request.sign(&signing_key)?;

    println!("OK");
    std::io::stdout().flush().ok();

    print!("Pushing file... ");
    std::io::stdout().flush().ok();

    file.seek(SeekFrom::Start(0))?;

    api.push(&request, &file_signature, file)
}

fn pull(filename: &str, download_dir: impl AsRef<Path>, api: impl Api) -> Result<()> {
    let signing_key = Keyring.get_signing_key()?;
    let request = SignableRequest::new(filename.to_string(), signing_key.verifying_key())?;
    let request = request.sign(&signing_key)?;
    let mut temp_file = NamedTempFile::new()?;

    print!("Downloading file... ");
    std::io::stdout().flush().ok();

    let file_signature_from_server = api.pull(&request, temp_file.as_file())?;

    println!("OK");
    std::io::stdout().flush().ok();

    print!("Calculating signature... ");
    std::io::stdout().flush().ok();
    let digest = calc_digest(temp_file.as_file_mut())?;
    let file_signature = signing_key.sign_digest(digest);

    if file_signature != file_signature_from_server {
        bail!("Signature mismatch");
    }

    println!("OK");
    std::io::stdout().flush().ok();

    std::fs::create_dir_all(download_dir.as_ref())?;
    let new_name = download_dir.as_ref().join(request.filename());
    assert!(new_name.starts_with(download_dir));
    temp_file.persist(&new_name)?;

    println!("File saved to {:?}", new_name);

    Ok(())
}

fn calc_digest(file: &mut File) -> Result<Hasher> {
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Hasher::default();
    let mut buffer = vec![0; 64 * 1024]; // 64 KB
    loop {
        let size = reader.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }

    Ok(hasher)
}

fn main() {
    let matches = cli().get_matches();
    let config: Config = serde_json::from_reader(
        File::open("client_config.json").expect("Unable to open config file"),
    )
    .expect("Unable to parse config file");

    match matches.subcommand() {
        Some(("regenerate-keys", _)) => {
            Keyring
                .regenerate_keypair()
                .expect("Error during keypair regeneration");
            println!("New keypair generated successfully!");
        }
        Some(("push", sub_matches)) => {
            let path = sub_matches
                .get_one::<String>("PATH")
                .expect("Path of file must be provided");
            let path = PathBuf::from_str(path.as_str()).expect("Unable to parse path");
            push(path, Keyring, HttpClient::new(config.server_url)).expect("Failed to upload file")
        }
        Some(("pull", sub_matches)) => {
            let filename = sub_matches
                .get_one::<String>("FILENAME")
                .expect("Filename must be provided");
            pull(
                filename,
                config.download_dir,
                HttpClient::new(config.server_url),
            )
            .expect("Filed to download file")
        }
        Some((cmd, _)) => unimplemented!("{cmd}"),
        None => unreachable!(),
    }
}
