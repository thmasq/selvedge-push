use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use selvedge_push::AppState;
use selvedge_push::config::Config;
use selvedge_push::heartbeat::{HeartbeatStore, spawn_sweeper};
use selvedge_push::routes::build_router;
use selvedge_push::webpush::ReqwestPushTransport;
use selvedge_push::webpush::vapid::{VapidKey, generate_vapid_keypair};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;

const HEARTBEAT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().any(|arg| arg == "--generate-vapid-keys") {
        return run_generate_vapid_keys();
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("selvedge_push=info,tower_http=info")),
        )
        .init();

    let (config, vapid_private_key) = match Config::from_env() {
        Ok((cfg, key)) => (Arc::new(cfg), key),
        Err(err) => {
            tracing::error!(error = %err, "invalid configuration");
            return ExitCode::FAILURE;
        }
    };

    let vapid = match VapidKey::parse(vapid_private_key.expose()) {
        Ok(key) => Arc::new(key),
        Err(err) => {
            tracing::error!(error = %err, "failed to load VAPID_PRIVATE_KEY");
            return ExitCode::FAILURE;
        }
    };

    drop(vapid_private_key);

    let transport = match ReqwestPushTransport::new(config.outbound_timeout) {
        Ok(t) => Arc::new(t),
        Err(err) => {
            tracing::error!(error = %err, "failed to initialize outbound HTTP client");
            return ExitCode::FAILURE;
        }
    };

    let heartbeats = Arc::new(HeartbeatStore::new(
        config.heartbeat_ttl,
        config.max_heartbeats,
    ));
    let sweeper = spawn_sweeper(heartbeats.clone(), HEARTBEAT_SWEEP_INTERVAL);

    let state = AppState {
        push_semaphore: Arc::new(Semaphore::new(config.max_concurrent_pushes)),
        config: config.clone(),
        vapid,
        heartbeats,
        transport,
    };

    let app = build_router(state);

    let listener = match TcpListener::bind(config.bind_addr).await {
        Ok(l) => l,
        Err(err) => {
            tracing::error!(addr = %config.bind_addr, error = %err, "failed to bind listener");
            sweeper.abort();
            return ExitCode::FAILURE;
        }
    };

    tracing::info!(
        addr = %config.bind_addr,
        allowed_app_id = %config.allowed_app_id,
        "selvedge-push listening"
    );

    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;

    sweeper.abort();

    if let Err(err) = serve_result {
        tracing::error!(error = %err, "server exited with error");
        return ExitCode::FAILURE;
    }

    tracing::info!("selvedge-push shut down cleanly");
    ExitCode::SUCCESS
}

fn run_generate_vapid_keys() -> ExitCode {
    match generate_vapid_keypair() {
        Ok(keys) => {
            println!("VAPID_PRIVATE_KEY={}", keys.private_key_b64.as_str());
            println!("SELVEDGE_VAPID_PUBLIC_KEY={}", keys.public_key_b64);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error generating VAPID keys: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sigterm) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sigterm.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
