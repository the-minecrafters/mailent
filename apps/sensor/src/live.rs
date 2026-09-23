use crate::{config::SensorConfig, error::SensorError, normalize, spool::BoundedSpooler};
use mailent_domain::SensorHeartbeat;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{process::Command, sync::watch, time::interval};
use tracing::{error, info, warn};

pub async fn run_live_listener(
    config: SensorConfig,
    zeek_bin: PathBuf,
    mut shutdown_rx: watch::Receiver<bool>,
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
    let spooler = Arc::new(BoundedSpooler::new(
        config.core_endpoint.clone(),
        spool_dir,
        config.buffer_capacity,
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
    let mut version_cmd = Command::new(&zeek_bin);
    version_cmd.arg("--version");
    version_cmd.current_dir(&work_path);
    let version_out = version_cmd.output().await.map_err(|e| {
        SensorError::Zeek(format!(
            "Failed to run Zeek binary '{}': {e}",
            zeek_bin.display()
        ))
    })?;
    let zeek_version = String::from_utf8_lossy(&version_out.stdout)
        .trim()
        .to_string();
    info!(version = %zeek_version, "Zeek verified successfully");

    // Spawn Zeek process on the interface
    let mut zeek_child = Command::new(&zeek_bin)
        .arg("-b")
        .arg("-i")
        .arg(&config.interface)
        .arg("-C") // ignore checksums for live interface sniffing
        .arg("mailent")
        .current_dir(&work_path)
        .spawn()
        .map_err(|e| {
            SensorError::Zeek(format!("Failed to spawn Zeek on {}: {e}", config.interface))
        })?;

    info!(pid = ?zeek_child.id(), "Zeek live capture process running");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string());

    let mut heartbeat_ticker = interval(Duration::from_secs(10));
    let mut poll_ticker = interval(Duration::from_secs(2));
    let mut seen_observation_ids = std::collections::HashSet::new();

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Shutdown signal received; stopping Zeek live listener");
                    break;
                }
            }
            status = zeek_child.wait() => {
                match status {
                    Ok(exit_status) => {
                        warn!("Zeek process exited with: {exit_status}");
                        break;
                    }
                    Err(e) => {
                        error!("Error waiting on Zeek process: {e}");
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
                if let Err(e) = client.post(&hb_url).json(&hb).send().await {
                    warn!(error = %e, "Sensor heartbeat failed; Core may be offline");
                }
            }
        }
    }

    // Gracefully terminate Zeek child
    let _ = zeek_child.kill().await;
    info!("Zeek process killed; draining remaining spool");
    spooler.drain_pending().await;
    info!("Mailent Sensor live listener stopped cleanly");

    Ok(())
}
