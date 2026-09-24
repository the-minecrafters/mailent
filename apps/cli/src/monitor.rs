use crate::credentials::{self, load_credentials};
use std::{path::PathBuf, time::Duration};

pub async fn run(interface: String, zeek: Option<PathBuf>) -> Result<(), String> {
    if interface.trim().is_empty() || interface.starts_with('-') {
        return Err("Choose a network interface, for example --interface eth0.".into());
    }
    let creds = load_credentials().ok_or("Run 'mailent login' before starting live monitoring.")?;
    let mut headers = reqwest::header::HeaderMap::new();
    let mut authorization =
        reqwest::header::HeaderValue::from_str(&format!("Bearer {}", creds.device_token))
            .map_err(|e| e.to_string())?;
    authorization.set_sensitive(true);
    headers.insert(reqwest::header::AUTHORIZATION, authorization);
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let status_url = format!(
        "{}/api/v1/devices/status",
        creds.server_url.trim_end_matches('/')
    );
    let response = client
        .get(&status_url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if credentials::handle_rejection(response.status(), &creds)? {
        return Ok(());
    }
    response.error_for_status().map_err(|e| e.to_string())?;
    let zeek = crate::locate_zeek(zeek.as_deref())?;
    let config = mailent_sensor::SensorConfig {
        sensor_id: format!("device-{}", creds.device_id),
        site_id: creds
            .organization_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        interface: interface.clone(),
        core_endpoint: creds.server_url.clone(),
        ..Default::default()
    };
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let listener =
        mailent_sensor::live::run_live_listener_with_client(config, zeek, shutdown, client.clone());
    tokio::pin!(listener);
    println!("Starting Zeek mail-traffic monitoring on {interface}. Press Ctrl+C to stop.");
    let mut access_check = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            result = &mut listener => return result.map_err(|e| e.to_string()),
            _ = tokio::signal::ctrl_c() => break,
            _ = access_check.tick() => {
                if !credentials::still_current(&creds) { println!("Signed out. Monitoring stopped."); break; }
                match client.get(&status_url).send().await {
                    Ok(response) if credentials::handle_rejection(response.status(), &creds)? => break,
                    Ok(response) if !response.status().is_success() => { eprintln!("Workspace unavailable; stopping live monitoring."); break; }
                    Err(_) => { eprintln!("Cannot verify workspace access; stopping live monitoring. Reconnect and run the command again."); break; }
                    _ => {}
                }
            }
        }
    }
    let _ = stop.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(7), &mut listener).await;
    Ok(())
}
