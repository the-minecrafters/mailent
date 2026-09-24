use crate::{config::SensorConfig, error::SensorError, normalize, spool::BoundedSpooler};
use mailent_domain::SensorHeartbeat;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{process::Command, sync::watch, time::interval};
use tracing::{error, info, warn};

pub async fn run_live_listener(
    config: SensorConfig,
    zeek_bin: PathBuf,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), SensorError> {
    let client = reqwest::Client::builder()
        .default_headers(crate::auth_headers())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| SensorError::Submit(e.to_string()))?;
    run_live_listener_with_client(config, zeek_bin, shutdown_rx, client).await
}

pub async fn run_live_listener_with_client(
    config: SensorConfig,
    zeek_bin: PathBuf,
    mut shutdown_rx: watch::Receiver<bool>,
    client: reqwest::Client,
) -> Result<(), SensorError> {
    info!(
        sensor_id = %config.sensor_id,
        site_id = %config.site_id,
        interface = %config.interface,
        core = %config.core_endpoint,
        "Starting Mailent Sensor live listener"
    );

    let spool_dir = PathBuf::from(
        std::env::var("MAILENT_SENSOR_SPOOL_DIR").unwrap_or_else(|_| "/tmp/mailent-spool".into()),
    );
    let spooler = Arc::new(BoundedSpooler::with_client(
        config.core_endpoint.clone(),
        spool_dir,
        config.buffer_capacity,
        client.clone(),
    ));

    // Prepare temporary directory for Zeek live execution
    let work = tempfile::tempdir()?;
    let work_path = work.path().to_path_buf();

    tokio::fs::create_dir_all(work_path.join("mailent")).await?;
    tokio::fs::write(
        work_path.join("mailent/__load__.zeek"),
        include_str!("../../../zeek/mailent/__load__.zeek"),
    )
    .await?;
    tokio::fs::write(
        work_path.join("mailent/dpd.sig"),
        include_str!("../../../zeek/mailent/dpd.sig"),
    )
    .await?;

    // Check Zeek version
    let is_script = cfg!(windows)
        && zeek_bin
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"));

    let mut version_cmd = if is_script {
        let mut c = Command::new("cmd.exe");
        c.arg("/c").arg(&zeek_bin);
        c
    } else {
        Command::new(&zeek_bin)
    };
    version_cmd.arg("--version");
    version_cmd.current_dir(&work_path);
    let version_out = version_cmd.output().await.map_err(|e| {
        SensorError::Zeek(format!(
            "Failed to run Zeek binary '{}': {e}",
            zeek_bin.display()
        ))
    })?;
    if !version_out.status.success() {
        return Err(SensorError::Zeek(
            "Required Zeek could not start. Run 'mailent doctor'.".into(),
        ));
    }
    let zeek_version = String::from_utf8_lossy(&version_out.stdout)
        .trim()
        .to_string();
    info!(version = %zeek_version, "Zeek verified successfully");

    // Spawn Zeek process on the interface
    let mut zeek_child_cmd = if is_script {
        let mut c = Command::new("cmd.exe");
        c.arg("/c").arg(&zeek_bin);
        c
    } else {
        Command::new(&zeek_bin)
    };
    let mut zeek_child = zeek_child_cmd
        .arg("-b")
        .arg("-i")
        .arg(&config.interface)
        .arg("-C") // ignore checksums for live interface sniffing
        .arg("mailent")
        .arg("-f")
        .arg("tcp port 25 or tcp port 465 or tcp port 587 or tcp port 110 or tcp port 995 or tcp port 143 or tcp port 993")
        .kill_on_drop(true)
        .current_dir(&work_path)
        .spawn()
        .map_err(|e| {
            SensorError::Zeek(format!("Failed to spawn Zeek on {}: {e}", config.interface))
        })?;

    info!(pid = ?zeek_child.id(), "Zeek live capture process running");

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string());

    let mut heartbeat_ticker = interval(Duration::from_secs(10));
    let mut poll_ticker = interval(Duration::from_secs(2));
    let mut seen_observation_ids = std::collections::HashSet::new();

    let mut failure = None;
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    info!("Shutdown signal received; stopping Zeek live listener");
                    break;
                }
            }
            status = zeek_child.wait() => {
                match status {
                    Ok(exit_status) => {
                        failure = Some(SensorError::Zeek(format!("Live capture stopped ({exit_status}). Check the interface and packet-capture permissions.")));
                        break;
                    }
                    Err(e) => {
                        error!("Error waiting on Zeek process: {e}");
                        failure = Some(SensorError::Zeek(e.to_string()));
                        break;
                    }
                }
            }
            _ = poll_ticker.tick() => {
                // Read any new logs in work_path
                let fake_sha = format!("live-{}", config.interface);
                if let Ok(observations) = normalize::normalize(&work_path, &fake_sha, &config.sensor_id, &zeek_version) {
                    for obs in observations {
                        if seen_observation_ids.insert(obs.observation_id) {
                            info!(observation_id = %obs.observation_id, flow = %obs.flow, "New observation captured from live interface");
                            spooler.submit(obs).await;
                        }
                    }
                }
                // Try to drain spooled observations to Core
                spooler.drain_pending().await;
            }
            _ = heartbeat_ticker.tick() => {
                let stats = spooler.stats();
                let hb = SensorHeartbeat {
                    sensor_id: config.sensor_id.clone(),
                    site_id: config.site_id.clone(),
                    hostname: hostname.clone(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    mode: "live_listener".to_string(),
                    interface: Some(config.interface.clone()),
                    observations_processed: stats.processed,
                    observations_spooled: stats.spooled,
                    observations_dropped: stats.dropped,
                };

                let hb_url = format!("{}/api/v1/sensors/heartbeat", config.core_endpoint.trim_end_matches('/'));
                match client.post(&hb_url).json(&hb).send().await {
                    Ok(response) if response.status() == reqwest::StatusCode::UNAUTHORIZED || response.status() == reqwest::StatusCode::FORBIDDEN => {
                        failure = Some(SensorError::Submit("Workspace access was removed. Live monitoring stopped.".into()));
                        break;
                    }
                    Ok(response) if !response.status().is_success() => warn!(status = %response.status(), "Collector heartbeat rejected"),
                    Err(e) => warn!(error = %e, "Collector heartbeat failed; workspace may be offline"),
                    _ => {}
                }
            }
        }
    }

    // SIGTERM lets container runners remove their container and lets Zeek flush logs.
    #[cfg(unix)]
    if let Some(pid) = zeek_child.id() {
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .await;
    }
    if tokio::time::timeout(Duration::from_secs(5), zeek_child.wait())
        .await
        .is_err()
    {
        let _ = zeek_child.kill().await;
    }
    // Never send queued results after access is revoked or the caller stops.
    if let Some(error) = failure {
        return Err(error);
    }
    info!("Mailent live monitoring stopped");
    Ok(())
}
