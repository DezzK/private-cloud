use anyhow::Result;
use ed25519_dalek::ed25519::signature::digest::Update;
use ed25519_dalek::{DigestVerifier, Signature, VerifyingKey};
use futures_util::{Stream, StreamExt, TryFutureExt};
use http::header::CONTENT_TYPE;
use http::HeaderName;
use log::{error, info};
use shared::consts::PARAM_FILE_SIGNATURE;
use shared::hasher::Hasher;
use std::str::FromStr;
use tokio_util::codec::{BytesCodec, FramedRead};
use warp::http::{HeaderValue, StatusCode};
use warp::hyper::Body;
use warp::reply::Response;
use warp::{Buf, Reply};

use shared::SignableRequest;

use crate::storage::FileWriter;
use crate::{storage, CONFIG};

pub async fn download(
    filename: HeaderValue,
    pubkey: HeaderValue,
    time: HeaderValue,
    request_signature: HeaderValue,
) -> Response {
    process_result(download_internal(filename, pubkey, time, request_signature).await)
}

async fn download_internal(
    filename: HeaderValue,
    pubkey: HeaderValue,
    time: HeaderValue,
    request_signature: HeaderValue,
) -> Result<Response> {
    let filename = filename.to_str()?;
    let pubkey = pubkey.to_str()?;
    let time = u64::from_str(time.to_str()?)?;
    let request_signature = request_signature.to_str()?;

    info!("Download: {filename}, pubkey: {pubkey}, time: {time}, request signature: {request_signature}");

    let request_signature = Signature::from_slice(&bs58::decode(request_signature).into_vec()?)?;
    let pubkey = VerifyingKey::try_from(bs58::decode(pubkey).into_vec()?.as_slice())?;
    let download_request = SignableRequest::with_time(filename.to_string(), pubkey, time);

    download_request.check_signature(&request_signature)?;

    let (file_path, signature_path) = storage::get_file_paths(
        &CONFIG.storage_path,
        download_request.pubkey(),
        download_request.filename(),
    )
    .await?;

    let signature = tokio::fs::read(signature_path).await?;
    let stream = tokio::fs::File::open(file_path)
        .map_ok(|file| FramedRead::new(file, BytesCodec::new()))
        .try_flatten_stream();

    let body = Body::wrap_stream(stream);

    Ok(http::Response::builder()
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )
        .header(
            HeaderName::from_static(PARAM_FILE_SIGNATURE),
            HeaderValue::from_str(&bs58::encode(&signature).into_string())?,
        )
        .body(body)?)
}

pub async fn upload(
    filename: HeaderValue,
    pubkey: HeaderValue,
    time: HeaderValue,
    request_signature: HeaderValue,
    file_signature: HeaderValue,
    body: impl Stream<Item = Result<impl Buf, warp::Error>> + Unpin,
) -> Response {
    process_result(
        upload_internal(
            filename,
            pubkey,
            time,
            request_signature,
            file_signature,
            body,
        )
        .await,
    )
}

async fn upload_internal(
    filename: HeaderValue,
    pubkey: HeaderValue,
    time: HeaderValue,
    request_signature: HeaderValue,
    file_signature: HeaderValue,
    body: impl Stream<Item = Result<impl Buf, warp::Error>> + Unpin,
) -> Result<impl Reply> {
    let filename = filename.to_str()?;
    let pubkey = pubkey.to_str()?;
    let time = u64::from_str(time.to_str()?)?;
    let request_signature = request_signature.to_str()?;
    let file_signature = file_signature.to_str()?;

    info!("Upload: {filename}, pubkey: {pubkey}, time: {time}, request signature: {request_signature}, file signature: {file_signature}");

    let pubkey = VerifyingKey::try_from(bs58::decode(pubkey).into_vec()?.as_slice())?;
    let request_signature = Signature::from_slice(&bs58::decode(request_signature).into_vec()?)?;
    let file_signature = Signature::from_slice(&bs58::decode(file_signature).into_vec()?)?;

    let upload_request = SignableRequest::with_time(filename.to_string(), pubkey, time);

    upload_request.check_signature(&request_signature)?;

    info!("Request signature OK. Started writing file.");

    let mut hasher = Hasher::default();
    let mut file_writer = FileWriter::new().await?;
    match write_body(&mut file_writer, &mut hasher, body).await {
        Ok(()) => {
            pubkey.verify_digest(hasher, &file_signature)?;
            file_writer
                .finalize(
                    upload_request.filename(),
                    upload_request.pubkey(),
                    &file_signature,
                )
                .await?;
        }
        Err(err) => {
            error!("File write error: {:?}", err);
            file_writer.drop_temp_file().await?;
            return Err(err);
        }
    }

    Ok(StatusCode::OK)
}

async fn write_body(
    file_writer: &mut FileWriter,
    hasher: &mut Hasher,
    mut body: impl Stream<Item = Result<impl Buf, warp::Error>> + Unpin,
) -> Result<()> {
    while let Some(buf) = body.next().await {
        let mut buf = buf?;
        while buf.remaining() > 0 {
            let chunk = buf.chunk();
            hasher.update(chunk);
            file_writer.append_chunk(chunk).await?;
            buf.advance(chunk.len());
        }
    }
    Ok(())
}

fn process_result(result: Result<impl Reply>) -> Response {
    match result {
        Ok(res) => res.into_response(),
        Err(error) => {
            error!("{}", error);
            warp::reply::with_status(error.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
                .into_response()
        }
    }
}
