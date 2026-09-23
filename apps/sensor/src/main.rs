use mailent_sensor::{SensorAgent, SensorConfig, SensorError, analyze, live};
use std::path::PathBuf;
use tokio::sync::watch;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .try_init();

    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), SensorError> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    if command == "--sample" {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &SensorAgent::new(SensorConfig::from_env()).generate_dev_sample()
            )?
        );
        return Ok(());
    }

    let default_zeek = PathBuf::from(std::env::var("MAILENT_ZEEK").unwrap_or_else(|_| {
        if std::path::Path::new("scripts/zeek-container").exists()
            && std::process::Command::new("zeek")
                .arg("--version")
                .output()
                .is_err()
        {
            "scripts/zeek-container".into()
        } else {
            "zeek".into()
        }
    }));

    if command == "listen" {
        let mut config = SensorConfig::from_env();
        let mut zeek = default_zeek;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-i" | "--interface" => {
                    config.interface = args.next().ok_or_else(|| {
                        SensorError::Input("-i/--interface requires an interface name".into())
                    })?;
                }
                "--zeek" => {
                    zeek = PathBuf::from(
                        args.next()
                            .ok_or_else(|| SensorError::Input("--zeek requires a path".into()))?,
                    );
                }
                "--core" => {
                    config.core_endpoint = args
                        .next()
                        .ok_or_else(|| SensorError::Input("--core requires a URL".into()))?;
                }
                _ => {
                    return Err(SensorError::Input(format!(
                        "unknown listen argument '{arg}'"
                    )));
                }
            }
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Received interrupt signal; initiating shutdown");
            let _ = shutdown_tx.send(true);
        });

        return live::run_live_listener(config, zeek, shutdown_rx).await;
    }

    if command != "analyze" {
        return Err(SensorError::Input(
            "usage: mailent-sensor [analyze CAPTURE | listen -i INTERFACE] [--zeek EXECUTABLE] [--core URL]".into(),
        ));
    }

    let path = PathBuf::from(
        args.next()
            .ok_or_else(|| SensorError::Input("capture path is required".into()))?,
    );
    let config = SensorConfig::from_env();
    let mut zeek = default_zeek;
    let mut core = config.core_endpoint;
    let mut json = false;
    let mut ignore_checksums = true;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--zeek" => {
                zeek = PathBuf::from(
                    args.next()
                        .ok_or_else(|| SensorError::Input("--zeek requires a path".into()))?,
                );
            }
            "--core" => {
                core = args
                    .next()
                    .ok_or_else(|| SensorError::Input("--core requires a URL".into()))?;
            }
            "--json" => json = true,
            "--ignore-checksums" => ignore_checksums = true,
            "--verify-checksums" => ignore_checksums = false,
            _ => return Err(SensorError::Input(format!("unknown argument {arg}"))),
        }
    }

    let analysis = analyze::analyze(&path, &zeek, &config.sensor_id, ignore_checksums).await?;
    for warning in &analysis.warnings {
        eprintln!("Warning: {warning}");
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&analysis)?);
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| SensorError::Submit(e.to_string()))?;
    let mut sent = 0;
    for observation in &analysis.observations {
        let bytes = mailent_events::wire::encode(observation)
            .map_err(|e| SensorError::Submit(e.to_string()))?;
        let response = client
            .post(format!(
                "{}/api/v1/observations",
                core.trim_end_matches('/')
            ))
            .header("Content-Type", "application/x-protobuf")
            .body(bytes)
            .send()
            .await
            .map_err(|e| {
                SensorError::Submit(format!("after {sent} sessions: {e}; replay is safe"))
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(SensorError::Submit(format!(
                "HTTP {status} after {sent} sessions: {}; replay is safe",
                response.text().await.unwrap_or_default()
            )));
        }
        sent += 1;
    }
    println!(
        "{}",
        serde_json::json!({
            "capture_sha256": analysis.capture_sha256,
            "submitted_sessions": sent,
            "warnings": analysis.warnings
        })
    );
    Ok(())
}
