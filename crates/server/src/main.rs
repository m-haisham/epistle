//! Service startup, tracing and orderly shutdown.

use epistle_auth::TokenProvider;
use epistle_core::Config;
use epistle_delivery::{Delivery, FileStore};
use epistle_store::Store;
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Error)]
enum Error {
    #[error("configuration failed: {0}")]
    Config(#[from] epistle_core::Error),
    #[error("filesystem or listener failed")]
    Io(#[from] std::io::Error),
    #[error("database startup failed")]
    Store(#[from] epistle_store::Error),
    #[error("credential provider startup failed")]
    Auth(#[from] epistle_auth::Error),
    #[error("delivery startup failed")]
    Delivery(#[from] epistle_delivery::Error),
    #[error("another instance already owns the data directory")]
    Locked,
    #[error("background task failed")]
    Task,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!(error = %e, "service stopped");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Error> {
    let config = prepare_config().await?;
    let lock = acquire_instance_lock(&config)?;

    let store = Store::open(&config.storage.data_dir.join("epistle.sqlite")).await?;
    let tokens = TokenProvider::new(store.clone(), config.clone())?;
    let files = FileStore::new(&config.storage.data_dir);
    files.sweep(&store, &config, true).await?;

    let delivery = Delivery::new(store.clone(), config.clone())?;
    let listener = tokio::net::TcpListener::bind(config.server.bind_addr).await?;

    let cancel = CancellationToken::new();
    let service = epistle_email::Service {
        store: store.clone(),
        tokens: tokens.clone(),
        files,
        config: config.clone(),
    };
    let mut tasks = spawn_workers(service, delivery, &cancel);

    let router = epistle_api::router(epistle_api::AppState {
        store: store.clone(),
        tokens,
        config,
    });
    tracing::info!(address = %listener.local_addr()?, epoch = store.epoch, "epistle listening");

    let outcome = serve_until_shutdown(listener, router, cancel, &mut tasks).await;
    store.close().await?;

    tracing::info!("shutdown complete; all workers and database writes drained");
    drop(lock);

    outcome
}

/// Loads settings and prepares the private data directory.
async fn prepare_config() -> Result<Arc<Config>, Error> {
    let mut config = Config::from_env()?;
    tokio::fs::create_dir_all(&config.storage.data_dir).await?;
    config.storage.data_dir = tokio::fs::canonicalize(&config.storage.data_dir).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(
            &config.storage.data_dir,
            std::fs::Permissions::from_mode(0o700),
        )
        .await?;
    }

    Ok(Arc::new(config))
}

/// Holds exclusive ownership until the caller finishes draining the store.
fn acquire_instance_lock(config: &Config) -> Result<std::fs::File, Error> {
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(config.storage.data_dir.join("instance.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| Error::Locked)?;

    Ok(lock)
}

fn spawn_workers(
    service: epistle_email::Service,
    delivery: Delivery,
    cancel: &CancellationToken,
) -> tokio::task::JoinSet<()> {
    let files = service.files.clone();
    let store = service.store.clone();
    let config = service.config.clone();

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(service.run(cancel.clone()));
    tasks.spawn(delivery.run(cancel.clone()));
    tasks.spawn(run_retention(files, store, config, cancel.clone()));

    tasks
}

async fn run_retention(
    files: FileStore,
    store: Store,
    config: Arc<Config>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(60)) => {
                if let Err(e) = files.sweep(&store, &config, false).await {
                    tracing::error!(error = %e, "retention sweep failed");
                }
            }
        }
    }

    tracing::info!("retention worker stopped");
}

/// Stops accepting work, then drains HTTP handlers and every worker.
async fn serve_until_shutdown(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    cancel: CancellationToken,
    tasks: &mut tokio::task::JoinSet<()>,
) -> Result<(), Error> {
    let http_stop = cancel.clone();
    let server = std::future::IntoFuture::into_future(
        axum::serve(listener, router).with_graceful_shutdown(http_stop.cancelled_owned()),
    );
    tokio::pin!(server);

    let (mut outcome, http_finished) = tokio::select! {
        result = &mut server => (result.map_err(Error::Io), true),
        _ = shutdown() => (Ok(()), false),
        _ = tasks.join_next() => (Err(Error::Task), false),
    };

    tracing::info!("shutdown requested; draining HTTP handlers and workers");
    cancel.cancel();

    // Do not abort token refreshes, file writes or webhook acknowledgments.
    // Each worker stops at a durable boundary and network calls have watchdogs.
    if !http_finished && let Err(error) = (&mut server).await {
        outcome = Err(Error::Io(error));
    }

    while let Some(result) = tasks.join_next().await {
        if result.is_err() {
            tracing::error!("background task panicked during shutdown");
            outcome = Err(Error::Task);
        }
    }

    outcome
}

async fn shutdown() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = term.recv() => {},
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
