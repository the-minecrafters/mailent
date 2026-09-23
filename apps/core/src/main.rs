use mailent_core::{api::create_router, config::CoreConfig, state::AppState};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let config = CoreConfig::from_env();
    let production = config.environment == "production";
    let auth = mailent_core::auth::AuthConfig::from_env(production)?;
    if production && config.database_url.is_none() {
        return Err("MAILENT_DATABASE_URL is required in production".into());
    }
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or(tracing_subscriber::EnvFilter::try_new(&config.log_level)?),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let addr = config.socket_addr()?;
    let mut state = AppState::from_config(&config).await?;
    if let Some(path) = &config.policy_path {
        state.policy_pack = std::sync::Arc::new(mailent_policy::PolicyPack::from_yaml(
            &std::fs::read_to_string(path)?,
        )?);
    }
    state.policy_pack.validate()?;

    tracing::info!(
        host = %config.host,
        port = %config.port,
        environment = %config.environment,
        "Starting Mailent Core control plane service"
    );

    mailent_core::scheduler::start_intelligence_refresh_scheduler(state.clone());
    mailent_core::scheduler::start_verification_scheduler(state.clone());

    mailent_core::probes::recover_stale_probes(&state).await?;
    let recovery_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(e) = mailent_core::probes::recover_stale_probes(&recovery_state).await {
                tracing::error!(error = %e, "Probe recovery failed");
            }
        }
    });
    let mut app = mailent_core::auth::protect(create_router(state), auth);
    if let Ok(directory) = std::env::var("MAILENT_WEB_DIR") {
        use tower_http::services::{ServeDir, ServeFile};
        app = app.fallback_service(
            ServeDir::new(&directory).fallback(ServeFile::new(format!("{directory}/index.html"))),
        );
    }
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("Mailent Core listening on http://{}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
