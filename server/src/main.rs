use std::net::SocketAddr;
use std::path::PathBuf;

use log::info;
use once_cell::sync::Lazy;
use warp::Filter;

use shared::consts::*;

mod handlers;
mod storage;

#[derive(Debug, serde::Deserialize)]
pub struct ServerConfig {
    listen_addr: SocketAddr,
    max_file_size: u64,
    storage_path: PathBuf,
}

pub static CONFIG: Lazy<ServerConfig> = Lazy::new(|| {
    serde_json::from_str(
        &std::fs::read_to_string("server_config.json").expect("Failed to read server config file"),
    )
    .map(|mut config: ServerConfig| {
        config.storage_path = config
            .storage_path
            .canonicalize()
            .expect("Failed to canonicalize storage path");
        config
    })
    .expect("Failed to parse server config file")
});

#[tokio::main]
async fn main() {
    log4rs::init_file("log_config.yml", Default::default()).expect("Error initializing logging");

    let download = warp::path(METHOD_DOWNLOAD)
        .and(warp::header::value(PARAM_FILENAME))
        .and(warp::header::value(PARAM_PUBKEY))
        .and(warp::header::value(PARAM_TIME))
        .and(warp::header::value(PARAM_REQUEST_SIGNATURE))
        // .and(warp::header::headers_cloned())
        .then(handlers::download);

    let upload = warp::post().and(
        warp::path(METHOD_UPLOAD)
            .and(warp::header::value(PARAM_FILENAME))
            .and(warp::header::value(PARAM_PUBKEY))
            .and(warp::header::value(PARAM_TIME))
            .and(warp::header::value(PARAM_REQUEST_SIGNATURE))
            .and(warp::header::value(PARAM_FILE_SIGNATURE))
            .and(warp::body::stream())
            .and(warp::body::content_length_limit(CONFIG.max_file_size))
            .then(handlers::upload),
    );

    let routes = download.or(upload);

    let (addr, web_server) =
        warp::serve(routes).bind_with_graceful_shutdown(CONFIG.listen_addr, async move {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to listen to shutdown signal");
            info!("CTRL+C received");
        });

    let web_server_task = tokio::task::spawn(web_server);

    info!("Started web server on {addr}");

    tokio::join!(web_server_task).0.expect("Failed to run task");

    info!("Gracefully shut down");
}
