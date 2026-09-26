use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use clap::Subcommand;
use mailent_domain::{AgentJob, AgentJobType};
use mailent_scanner::DomainScanner;
use serde_json::json;
use tracing::warn;

use crate::credentials::{self, load_credentials};
use crate::engine::locate_zeek;

#[derive(Subcommand, Debug, Clone)]
pub enum CompanionCommands {
    /// Install the Mailent companion as a background systemd service
    Install {
        /// Install as a system service (/etc/systemd/system) instead of user service (~/.config/systemd/user)
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Start the Mailent companion background service
    Start {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Stop the Mailent companion background service
    Stop {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Restart the Mailent companion background service
    Restart {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Inspect companion service state and workspace connectivity
    Status {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Uninstall the Mailent companion background service
    Uninstall {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Run the local companion listener directly in the foreground
    Run {
        /// Polling interval for queued workspace checks in seconds
        #[arg(long, default_value_t = 5)]
        poll_interval: u64,
        /// Heartbeat telemetry interval in seconds
        #[arg(long, default_value_t = 30)]
        heartbeat_interval: u64,
        /// Loopback bridge port for local browser acquisition
        #[arg(long, default_value_t = 15488)]
        port: u16,
    },
}

pub async fn run_companion_command(cmd: CompanionCommands) -> Result<(), String> {
    match cmd {
        CompanionCommands::Install { system } => run_install(system),
        CompanionCommands::Start { system } => run_start(system),
        CompanionCommands::Stop { system } => run_stop(system),
        CompanionCommands::Restart { system } => run_restart(system),
        CompanionCommands::Status { system } => run_status(system).await,
        CompanionCommands::Uninstall { system } => run_uninstall(system),
        CompanionCommands::Run {
            poll_interval,
            heartbeat_interval,
            port,
        } => run_daemon(poll_interval, heartbeat_interval, port).await,
    }
}

fn get_unit_path(system: bool) -> Result<PathBuf, String> {
    if system {
        Ok(PathBuf::from("/etc/systemd/system/mailent-companion.service"))
    } else {
        let home =
            std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
        let user_systemd_dir = PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user");
        fs::create_dir_all(&user_systemd_dir)
            .map_err(|e| format!("Failed to create {}: {e}", user_systemd_dir.display()))?;
        Ok(user_systemd_dir.join("mailent-companion.service"))
    }
}

fn require_systemd() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err(
            "Service management via systemd is only supported on Linux.\nTo run the companion on Windows or macOS, run directly in foreground or via Task Scheduler:\n  mailent companion run".to_string()
        );
    }
    Ok(())
}

pub fn check_service_state(system: bool) -> &'static str {
    if !cfg!(target_os = "linux") {
        return "Unsupported (non-Linux)";
    }
    let mut cmd = Command::new("systemctl");
    if !system {
        cmd.arg("--user");
    }
    cmd.args(["is-active", "mailent-companion.service"]);
    match cmd.output() {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s == "active" {
                "Active (running)"
            } else if s == "inactive" {
                "Inactive (stopped)"
            } else if s == "failed" {
                "Failed (error)"
            } else {
                "Not installed / stopped"
            }
        }
        Err(_) => "systemctl unavailable",
    }
}

pub async fn check_bridge_readiness(port: u16) -> (bool, Option<serde_json::Value>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(1500))
        .build();
    let Ok(client) = client else {
        return (false, None);
    };
    let url = format!("http://127.0.0.1:{port}/status");
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let val = resp.json::<serde_json::Value>().await.ok();
            (true, val)
        }
        _ => (false, None),
    }
}

pub fn auto_install_user_service() -> Result<PathBuf, String> {
    require_systemd()?;
    let zeek_path = locate_zeek(None).unwrap_or_else(|_| PathBuf::from("/usr/bin/zeek"));
    let _creds = load_credentials().ok_or_else(|| {
        "This device is not linked to a Mailent workspace yet.\nPlease run 'mailent login' first before installing the companion service.".to_string()
    })?;

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to determine current executable path: {e}"))?;
    let canonical_exe = fs::canonicalize(&exe_path).unwrap_or(exe_path);
    let exe_str = canonical_exe
        .to_str()
        .ok_or("Invalid executable path string")?;

    let unit_path = get_unit_path(false)?;
    let zeek_path_str = zeek_path.display().to_string();
    let credentials_path = credentials::credentials_path().display().to_string();
    for value in [exe_str, &zeek_path_str, &credentials_path] {
        if value.contains(['\n', '\r', '"', '%', '\\']) {
            return Err("Unsupported character in the installation path.".into());
        }
    }
    let unit_content = format!(
        r#"[Unit]
Description=Mailent local execution companion
Documentation=https://github.com/the-minecrafters/mailent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="{exe_str}" companion run --port 15488
Restart=on-failure
RestartSec=5s
UMask=0077
Environment="MAILENT_ZEEK={zeek_path_str}"
Environment="MAILENT_CREDENTIALS_PATH={credentials_path}"
Environment=PATH=/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
"#
    );

    fs::write(&unit_path, unit_content)
        .map_err(|e| format!("Failed to write unit file {}: {e}", unit_path.display()))?;

    let mut reload_cmd = Command::new("systemctl");
    reload_cmd.args(["--user", "daemon-reload"]);
    let _ = reload_cmd.status();

    let mut enable_cmd = Command::new("systemctl");
    enable_cmd.args(["--user", "enable", "--now", "mailent-companion.service"]);
    let enable_res = enable_cmd
        .status()
        .map_err(|e| format!("Failed to enable systemd service: {e}"))?;

    if !enable_res.success() {
        return Err("systemctl enable --now mailent-companion.service failed".to_string());
    }

    Ok(unit_path)
}

fn run_install(system: bool) -> Result<(), String> {
    require_systemd()?;
    let zeek_path = locate_zeek(None)?;
    let creds = load_credentials().ok_or_else(|| {
        "This device is not linked to a Mailent workspace yet.\nPlease run 'mailent login' first before installing the companion service.".to_string()
    })?;

    let unit_path = if !system {
        auto_install_user_service()?
    } else {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to determine current executable path: {e}"))?;
        let canonical_exe = fs::canonicalize(&exe_path).unwrap_or(exe_path);
        let exe_str = canonical_exe
            .to_str()
            .ok_or("Invalid executable path string")?;

        let unit_path = get_unit_path(true)?;
        let zeek_path_str = zeek_path.display().to_string();
        let credentials_path = credentials::credentials_path().display().to_string();
        for value in [exe_str, &zeek_path_str, &credentials_path] {
            if value.contains(['\n', '\r', '"', '%', '\\']) {
                return Err("Unsupported character in the installation path.".into());
            }
        }
        let unit_content = format!(
            r#"[Unit]
Description=Mailent local execution companion
Documentation=https://github.com/the-minecrafters/mailent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart="{exe_str}" companion run --port 15488
Restart=on-failure
RestartSec=5s
UMask=0077
Environment="MAILENT_ZEEK={zeek_path_str}"
Environment="MAILENT_CREDENTIALS_PATH={credentials_path}"
Environment=PATH=/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
"#
        );

        fs::write(&unit_path, unit_content)
            .map_err(|e| format!("Failed to write unit file {}: {e}", unit_path.display()))?;

        let mut reload_cmd = Command::new("systemctl");
        reload_cmd.arg("daemon-reload");
        let _ = reload_cmd.status();

        let mut enable_cmd = Command::new("systemctl");
        enable_cmd.args(["enable", "--now", "mailent-companion.service"]);
        let enable_res = enable_cmd
            .status()
            .map_err(|e| format!("Failed to enable systemd service: {e}"))?;

        if !enable_res.success() {
            return Err("systemctl enable --now mailent-companion.service failed".to_string());
        }

        unit_path
    };

    println!("\n── 󰄬 Mailent Companion Installed Successfully ──");
    println!("  󰈙 Service Unit:  {}", unit_path.display());
    println!(
        "  󰒓 Mode:          {}",
        if system {
            "system service"
        } else {
            "user service"
        }
    );
    println!("  󰒍 Device Name:   {}", creds.device_name);
    println!("  󰌆 Device ID:     {}", creds.device_id);
    println!("  󰞀 Workspace:     {}", creds.server_url);
    println!("  󰒋 Local Bridge:  http://127.0.0.1:15488");
    println!("  󱐋 Auto-start:    Enabled (restart on failure)");
    println!("\nCompanion service is now active and ready for workspace execution.");
    println!("Check companion status at any time with: mailent companion status\n");

    Ok(())
}

fn run_start(system: bool) -> Result<(), String> {
    require_systemd()?;
    locate_zeek(None)?;
    let unit_path = get_unit_path(system)?;
    if !unit_path.exists() {
        return run_install(system);
    }
    let mut cmd = Command::new("systemctl");
    if !system {
        cmd.arg("--user");
    }
    cmd.args(["start", "mailent-companion.service"]);
    let res = cmd
        .status()
        .map_err(|e| format!("Failed to run systemctl: {e}"))?;
    if res.success() {
        println!("Mailent companion service started.");
        Ok(())
    } else {
        Err("Failed to start mailent-companion.service via systemctl".to_string())
    }
}

fn run_stop(system: bool) -> Result<(), String> {
    require_systemd()?;
    let mut cmd = Command::new("systemctl");
    if !system {
        cmd.arg("--user");
    }
    cmd.args(["stop", "mailent-companion.service"]);
    let res = cmd
        .status()
        .map_err(|e| format!("Failed to run systemctl: {e}"))?;
    if res.success() {
        println!("Mailent companion service stopped.");
        Ok(())
    } else {
        Err("Failed to stop mailent-companion.service via systemctl".to_string())
    }
}

fn run_restart(system: bool) -> Result<(), String> {
    require_systemd()?;
    locate_zeek(None)?;
    let mut cmd = Command::new("systemctl");
    if !system {
        cmd.arg("--user");
    }
    cmd.args(["restart", "mailent-companion.service"]);
    let res = cmd
        .status()
        .map_err(|e| format!("Failed to run systemctl: {e}"))?;
    if res.success() {
        println!("Mailent companion service restarted.");
        Ok(())
    } else {
        Err("Failed to restart mailent-companion.service via systemctl".to_string())
    }
}

fn run_uninstall(system: bool) -> Result<(), String> {
    require_systemd()?;
    let _ = run_stop(system);

    let mut disable_cmd = Command::new("systemctl");
    if !system {
        disable_cmd.arg("--user");
    }
    disable_cmd.args(["disable", "mailent-companion.service"]);
    let _ = disable_cmd.status();

    let unit_path = get_unit_path(system)?;
    if unit_path.exists() {
        fs::remove_file(&unit_path)
            .map_err(|e| format!("Failed to remove unit file {}: {e}", unit_path.display()))?;
    }

    let mut reload_cmd = Command::new("systemctl");
    if !system {
        reload_cmd.arg("--user");
    }
    reload_cmd.arg("daemon-reload");
    let _ = reload_cmd.status();

    println!("Mailent companion service uninstalled successfully.");
    Ok(())
}

async fn run_status(system: bool) -> Result<(), String> {
    let creds = load_credentials();

    println!("\n── 󱐋 Mailent Companion Status ──\n");

    let service_state = check_service_state(system);

    println!("  󱐋 Service State:   {}", service_state);
    println!(
        "  󰒓 Service Scope:   {}",
        if system { "system" } else { "user" }
    );

    match &creds {
        Some(c) => {
            println!("  󰒍 Device Name:     {}", c.device_name);
            println!("  󰌆 Device ID:       {}", c.device_id);
            println!(
                "  󰞀 Organization:    {}",
                c.organization_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "Default".to_string())
            );
            println!("  󰞀 Workspace:       {}", c.server_url);

            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .map_err(|e| e.to_string())?;

            let url = format!(
                "{}/api/v1/devices/status",
                c.server_url.trim_end_matches('/')
            );
            match client
                .get(&url)
                .header("Authorization", format!("Bearer {}", c.device_token))
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(json_data) = resp.json::<serde_json::Value>().await {
                        let agent_status = json_data
                            .get("device")
                            .and_then(|d| d.get("agent_status"))
                            .and_then(|s| s.as_str())
                            .unwrap_or("idle");
                        let completed_jobs = json_data
                            .get("device")
                            .and_then(|d| d.get("completed_jobs_count"))
                            .and_then(|c| c.as_u64())
                            .unwrap_or(0);
                        let last_heartbeat = json_data
                            .get("device")
                            .and_then(|d| d.get("last_heartbeat_at"))
                            .and_then(|t| t.as_str())
                            .unwrap_or("Never");

                        println!("  󰄬 Workspace Link:  Connected (authenticated)");
                        println!("  󰄬 Readiness:       {}", if agent_status == "idle" { "Ready" } else { agent_status });
                        println!("  󰈙 Completed Checks:{}", completed_jobs);
                        println!("  󰅐 Last Heartbeat:  {}", last_heartbeat);
                    }
                }
                Ok(resp) => {
                    if credentials::handle_rejection(resp.status(), c)? {
                        return Ok(());
                    }
                    println!(
                        "  󰀦 Workspace Link:  Unavailable (HTTP {})",
                        resp.status()
                    );
                }
                Err(e) => {
                    println!("  󰅖 Workspace Link:  Unreachable ({})", e);
                }
            }
        }
        None => {
            println!("  󰀦 Authentication:  Not configured (run 'mailent login' first)");
        }
    }
    println!();

    Ok(())
}

pub async fn run_daemon(
    poll_interval: u64,
    heartbeat_interval: u64,
    bridge_port: u16,
) -> Result<(), String> {
    let creds = load_credentials().ok_or("Run 'mailent login' to connect this device.")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| e.to_string())?;
    let base_url = creds.server_url.trim_end_matches('/');

    let zeek = locate_zeek(None)?;
    crate::installation::report_best_effort(&creds, base_url, Some(&zeek)).await;
    if !send_heartbeat(&client, base_url, &creds, "idle").await? {
        return Ok(());
    }

    // Start local companion bridge concurrently on 127.0.0.1
    let bridge_task = tokio::spawn(async move {
        if let Err(e) = crate::bridge::start_bridge_server(bridge_port).await {
            warn!("Local companion bridge error: {e}");
        }
    });

    println!("\n── 󱐋 Mailent Execution Companion ──");
    println!("  󰒍 Device:       {}", creds.device_name);
    println!("  󰒋 Local Bridge: http://127.0.0.1:{}", bridge_port);
    println!("  󰏗 Zeek:         {}", zeek.display());
    println!("  󰞀 Workspace:    {}", creds.server_url);
    println!("  󰄬 Readiness:    Ready (accepting workspace execution)");
    println!("\n  Press Ctrl+C to terminate.\n");

    let mut poll = tokio::time::interval(Duration::from_secs(poll_interval.clamp(1, 30)));
    let mut heartbeat = tokio::time::interval(Duration::from_secs(heartbeat_interval.clamp(1, 30)));
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                bridge_task.abort();
                return Ok(());
            }
            _ = heartbeat.tick() => {
                if !send_heartbeat(&client, base_url, &creds, "idle").await? {
                    bridge_task.abort();
                    return Ok(());
                }
            }
            _ = poll.tick() => {
                if !credentials::still_current(&creds) {
                    println!("Signed out. Execution stopped.");
                    bridge_task.abort();
                    return Ok(());
                }
                let response = client.post(format!("{base_url}/api/v1/agent/jobs/poll"))
                    .bearer_auth(&creds.device_token).json(&json!({})).send().await;
                match response {
                    Ok(resp) => {
                        if credentials::handle_rejection(resp.status(), &creds)? {
                            bridge_task.abort();
                            return Ok(());
                        }
                        if !resp.status().is_success() {
                            warn!("Check polling returned {}", resp.status());
                            continue;
                        }
                        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
                        if let Some(value) = body.get("job").filter(|v| !v.is_null()) {
                            let job: AgentJob = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
                            println!("  ↳ Executing check {}", job.id);
                            let work = execute_job(&client, base_url, &creds, job);
                            tokio::pin!(work);
                            let mut access_check = tokio::time::interval(Duration::from_secs(2));
                            loop {
                                tokio::select! {
                                    result = &mut work => {
                                        if !result? {
                                            bridge_task.abort();
                                            return Ok(());
                                        }
                                        break;
                                    }
                                    _ = tokio::signal::ctrl_c() => {
                                        bridge_task.abort();
                                        return Ok(());
                                    }
                                    _ = access_check.tick() => {
                                        if !send_heartbeat(&client, base_url, &creds, "busy").await? {
                                            bridge_task.abort();
                                            return Ok(());
                                        }
                                    }
                                }
                            }
                            if !send_heartbeat(&client, base_url, &creds, "idle").await? {
                                bridge_task.abort();
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => warn!("Cannot reach workspace: {e}"),
                }
            }
        }
    }
}

async fn send_heartbeat(
    client: &reqwest::Client,
    base_url: &str,
    creds: &credentials::DeviceCredentials,
    status: &str,
) -> Result<bool, String> {
    if !credentials::still_current(creds) {
        println!("Signed out. Companion stopped.");
        return Ok(false);
    }
    match client.post(format!("{base_url}/api/v1/agent/heartbeat"))
        .bearer_auth(&creds.device_token)
        .json(&json!({ "version": env!("CARGO_PKG_VERSION"), "capabilities": ["infrastructure_scan"], "status": status }))
        .send().await {
        Ok(response) => {
            if credentials::handle_rejection(response.status(), creds)? { return Ok(false); }
            if !response.status().is_success() { warn!("Workspace heartbeat returned {}", response.status()); }
        }
        Err(e) => warn!("Cannot send workspace heartbeat: {e}"),
    }
    Ok(true)
}

async fn execute_job(
    client: &reqwest::Client,
    base_url: &str,
    creds: &credentials::DeviceCredentials,
    job: AgentJob,
) -> Result<bool, String> {
    let token = &creds.device_token;
    match job.job_type {
        AgentJobType::InfrastructureAssessment {
            domain,
            timeout_seconds,
        } => {
            println!(
                "  ↳ Running infrastructure check for domain: {domain} (timeout: {timeout_seconds}s)"
            );

            let scanner_res = DomainScanner::new_live();
            let scanner = match scanner_res {
                Ok(s) => s,
                Err(e) => {
                    let err_msg = format!("Failed to initialize DomainScanner: {e}");
                    eprintln!("  [✗] {err_msg}");
                    return report_failure(client, base_url, creds, job.id, &err_msg).await;
                }
            };

            let result = tokio::time::timeout(
                Duration::from_secs(timeout_seconds.clamp(10, 240)),
                scanner.scan_domain(&domain),
            )
            .await;
            let result = match result {
                Ok(result) => result,
                Err(_) => {
                    return report_failure(
                        client,
                        base_url,
                        creds,
                        job.id,
                        "The device check exceeded its time limit.",
                    )
                    .await;
                }
            };
            match result {
                Ok(scan_result) => {
                    println!(
                        "  [✔] Scan completed for {domain}: {} endpoints checked, {} passed, Posture Grade: {}",
                        scan_result.endpoints_checked,
                        scan_result.endpoints_succeeded,
                        scan_result.assessment.posture_grade
                    );

                    let complete_url = format!("{base_url}/api/v1/agent/jobs/{}/complete", job.id);
                    let body = json!({
                        "assessment": scan_result.assessment,
                        "findings": scan_result.findings,
                        "assets": [],
                        "sessions": scan_result.sessions,
                        "output_summary": {
                            "domain": domain,
                            "endpoints_checked": scan_result.endpoints_checked,
                            "endpoints_succeeded": scan_result.endpoints_succeeded,
                            "endpoints_failed": scan_result.endpoints_failed,
                            "posture_score": scan_result.assessment.posture_score,
                            "posture_grade": scan_result.assessment.posture_grade,
                        }
                    });

                    match client
                        .post(&complete_url)
                        .header("Authorization", format!("Bearer {token}"))
                        .json(&body)
                        .send()
                        .await
                    {
                        Ok(resp) if resp.status().is_success() => {
                            println!("  [✔] Check {} reported to workspace", job.id);
                        }
                        Ok(resp) => {
                            if credentials::handle_rejection(resp.status(), creds)? {
                                return Ok(false);
                            }
                            eprintln!(
                                "  [!] Failed to report completion to workspace: HTTP {}",
                                resp.status()
                            );
                        }
                        Err(e) => {
                            eprintln!("  [!] Failed to report completion to workspace: {e}");
                        }
                    }
                }
                Err(e) => {
                    let err_msg = format!("Infrastructure scan failed: {e}");
                    eprintln!("  [✗] {err_msg}");
                    return report_failure(client, base_url, creds, job.id, &err_msg).await;
                }
            }
        }
        AgentJobType::ActiveVerification { endpoint } => {
            return report_failure(client, base_url, creds, job.id, &format!("This CLI supports domain checks. Individual endpoint verification is not available for {endpoint}.")).await;
        }
    }
    Ok(true)
}

async fn report_failure(
    client: &reqwest::Client,
    base_url: &str,
    creds: &credentials::DeviceCredentials,
    job_id: uuid::Uuid,
    error: &str,
) -> Result<bool, String> {
    let fail_url = format!("{base_url}/api/v1/agent/jobs/{job_id}/fail");
    let response = client
        .post(&fail_url)
        .bearer_auth(&creds.device_token)
        .json(&json!({ "error": error }))
        .send()
        .await;
    if let Ok(response) = response {
        return Ok(!credentials::handle_rejection(response.status(), creds)?);
    }
    Ok(true)
}
