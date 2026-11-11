mod auth;
mod cloudflare;
mod config;
mod crypto;
mod error;
mod http;
mod state;
mod store;
#[cfg(test)]
mod tests;

use error::{AppError, Result};
use std::{net::SocketAddr, path::Path, time::Duration};

#[tokio::main(worker_threads = 2)]
async fn main() {
    tracing_subscriber::fmt().json().with_target(false).init();
    if let Err(error) = run().await {
        tracing::error!(code = error.1, "cf-mtls-portal stopped");
        std::process::exit(1);
    }
}
async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("healthcheck") if args.len() == 1 => {
            let response = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(2))
                .build()
                .map_err(|_| AppError::internal())?
                .get("http://127.0.0.1:8080/healthz")
                .send()
                .await
                .map_err(|_| AppError::internal())?;
            if !response.status().is_success() {
                return Err(AppError::internal());
            }
            return Ok(());
        }
        Some("check-csr") if args.len() == 3 => {
            let text = std::fs::read_to_string(&args[1])?;
            let spki = crypto::check_csr(&text, &args[2])?;
            println!("CSR valid; SPKI SHA256 {spki}");
            return Ok(());
        }
        Some("import-legacy") if args.len() == 3 => {
            store::Store::import(Path::new(&args[1]), Path::new(&args[2]))?;
            println!("Imported offline database copy; original untouched");
            return Ok(());
        }
        Some("check-config") if args.len() == 2 => {
            config::Config::load(Path::new(&args[1]))
                .map_err(|_| AppError::bad("config", "配置验证失败。"))?;
            println!("Configuration valid");
            return Ok(());
        }
        Some("serve") if args.len() == 2 => (),
        _ => {
            println!(
                "cf-mtls-portal serve <config.toml>\ncf-mtls-portal check-config <config.toml>\ncf-mtls-portal check-csr <csr.pem> <expected-cn>\ncf-mtls-portal import-legacy <offline-source.sqlite3> <new-target.sqlite3>"
            );
            return Ok(());
        }
    }
    let config = config::Config::load(Path::new(&args[1]))
        .map_err(|_| AppError::bad("config", "配置验证失败，请核对示例与部署文档。"))?;
    let listen = config.listen;
    let state = state::State::new(config)?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen,"cf-mtls-portal started");
    axum::serve(
        listener,
        http::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}
async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _=tokio::signal::ctrl_c()=>{}, _=signal.recv()=>{} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
