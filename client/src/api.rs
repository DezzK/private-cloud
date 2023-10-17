use std::fs::File;
use std::io::{BufWriter, Write};

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::Signature;
use reqwest::blocking::Client;
use reqwest::header::HeaderName;
use reqwest::StatusCode;
use shared::consts::*;
use url::Url;

use shared::SignedRequest;

pub trait Api {
    fn push(&self, request: &SignedRequest, file_signature: &Signature, file: File) -> Result<()>;
    fn pull(&self, request: &SignedRequest, file: &File) -> Result<Signature>;
}

pub struct HttpClient {
    client: Client,
    server_url: Url,
}

impl HttpClient {
    pub fn new(server_url: Url) -> Self {
        let client = Client::new();

        Self { client, server_url }
    }
}

impl Api for HttpClient {
    fn push(&self, request: &SignedRequest, file_signature: &Signature, file: File) -> Result<()> {
        let pubkey_b58 = bs58::encode(request.pubkey()).into_string();
        let request_signature_b58 = bs58::encode(request.signature().to_bytes()).into_string();
        let file_signature_b58 = bs58::encode(file_signature.to_bytes()).into_string();

        let response = self
            .client
            .post(self.server_url.join(METHOD_UPLOAD)?)
            .header(HeaderName::from_static(PARAM_FILENAME), request.filename())
            .header(HeaderName::from_static(PARAM_PUBKEY), pubkey_b58)
            .header(HeaderName::from_static(PARAM_TIME), request.time())
            .header(
                HeaderName::from_static(PARAM_REQUEST_SIGNATURE),
                request_signature_b58,
            )
            .header(
                HeaderName::from_static(PARAM_FILE_SIGNATURE),
                file_signature_b58,
            )
            .body(file)
            .send()?;

        if response.status() == StatusCode::OK {
            println!("OK");
            std::io::stdout().flush().ok();
        } else {
            eprintln!("Server returned error status code: {}", response.status());
            eprintln!("{}", response.text()?);
            std::io::stderr().flush().ok();
        }

        Ok(())
    }

    fn pull(&self, request: &SignedRequest, file: &File) -> Result<Signature> {
        let pubkey_b58 = bs58::encode(request.pubkey()).into_string();
        let request_signature_b58 = bs58::encode(request.signature().to_bytes()).into_string();

        let mut response = self
            .client
            .get(self.server_url.join(METHOD_DOWNLOAD)?)
            .header(HeaderName::from_static(PARAM_FILENAME), request.filename())
            .header(HeaderName::from_static(PARAM_PUBKEY), pubkey_b58)
            .header(HeaderName::from_static(PARAM_TIME), request.time())
            .header(
                HeaderName::from_static(PARAM_REQUEST_SIGNATURE),
                request_signature_b58,
            )
            .send()?;

        if response.status() != StatusCode::OK {
            bail!(
                "Server returned error status code: {}\n{}",
                response.status(),
                response.text()?
            );
        }

        let file_signature_b58 = response
            .headers()
            .get(PARAM_FILE_SIGNATURE)
            .ok_or(anyhow!("Header not found: {PARAM_FILE_SIGNATURE}"))?
            .to_str()?;
        let file_signature = Signature::from_slice(&bs58::decode(file_signature_b58).into_vec()?)?;

        response.copy_to(&mut BufWriter::new(file))?;

        Ok(file_signature)
    }
}
