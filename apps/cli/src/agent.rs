use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use clap::Subcommand;
use mailent_domain::{AgentJob, AgentJobType};
use mailent_scanner::DomainScanner;
use serde_json::json;
use tracing::warn;

use crate::credentials::load_credentials;

#[derive(Subcommand, Debug, Clone)]
pub enum AgentCommands {
    /// Install the Mailent agent as a background systemd service
    Install {
        /// Install as a system service (/etc/systemd/system) instead of user service (~/.config/systemd/user)
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Start the Mailent agent background service
    Start {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Stop the Mailent agent background service
    Stop {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Restart the Mailent agent background service
    Restart {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Inspect agent service state and control plane telemetry
    Status {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Uninstall the Mailent agent systemd service
    Uninstall {
        #[arg(long, default_value_t = false)]
        system: bool,
    },
    /// Run the agent worker daemon directly in the foreground
    Run {
        /// Polling interval for queued jobs in seconds
        #[arg(long, default_value_t = 5)]
        poll_interval: u64,
        /// Heartbeat telemetry interval in seconds
        #[arg(long, default_value_t = 30)]
        heartbeat_interval: u64,
    },
}

pub async fn run_agent_command(cmd: AgentCommands) -> Result<(), String> {
    match cmd {
        AgentCommands::Install { system } => run_install(system),
        AgentCommands::Start { system } => run_start(system),
        AgentCommands::Stop { system } => run_stop(system),
        AgentCommands::Restart { system } => run_restart(system),
        AgentCommands::Status { system } => run_status(system).await,
        AgentCommands::Uninstall { system } => run_uninstall(system),
        AgentCommands::Run {
            poll_interval,
            heartbeat_interval,
        } => run_daemon(poll_interval, heartbeat_interval).await,
    }
}

fn get_unit_path(system: bool) -> Result<PathBuf, String> {
    if system {
        Ok(PathBuf::from("/etc/systemd/system/mailent-agent.service"))
    } else {
        let home =
            std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
        let user_systemd_dir = PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user");
        fs::create_dir_all(&user_systemd_dir)
            .map_err(|e| format!("Failed to create {}: {e}", user_systemd_dir.display()))?;
        Ok(user_systemd_dir.join("mailent-agent.service"))
    }
}

fn run_install(system: bool) -> Result<(), String> {
    let creds = load_credentials().ok_or_else(|| {
        "This device is not linked to a Mailent workspace yet.\nPlease run 'mailent login' first before installing the agent service.".to_string()
    })?;

    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to determine current executable path: {e}"))?;
    let canonical_exe = fs::canonicalize(&exe_path).unwrap_or(exe_path);
    let exe_str = canonical_exe
        .to_str()
        .ok_or("Invalid executable path string")?;

    let unit_path = get_unit_path(system)?;
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());

    let unit_content = format!(
        r#"[Unit]
Description=Mailent Scanning Agent
Documentation=https://github.com/the-minecrafters/mailent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe_str} agent run
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={home}/.config/mailent /tmp
Environment=PATH=/usr/local/bin:/usr/bin:/bin

[Install]
WantedBy=default.target
"#
    );

    fs::write(&unit_path, unit_content)
        .map_err(|e| format!("Failed to write unit file {}: {e}", unit_path.display()))?;

    let mut reload_cmd = Command::new("systemctl");
    if !system {
        reload_cmd.arg("--user");
    }
    reload_cmd.arg("daemon-reload");
    let _ = reload_cmd.status();

    let mut enable_cmd = Command::new("systemctl");
    if !system {
        enable_cmd.arg("--user");
    }
    enable_cmd.args(["enable", "--now", "mailent-agent.service"]);
    let enable_res = enable_cmd
        .status()
        .map_err(|e| format!("Failed to enable systemd service: {e}"))?;

    if !enable_res.success() {
        return Err("systemctl enable --now mailent-agent.service failed".to_string());
    }

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║             MAILENT AGENT INSTALLED SUCCESSFULLY         ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!("  • Service Unit:    {}", unit_path.display());
    println!(
        "  • Mode:            {}",
        if system {
            "system service"
        } else {
            "user service"
        }
    );
    println!("  • Device Name:     {}", creds.device_name);
    println!("  • Device ID:       {}", creds.device_id);
    println!("  • Control Plane:   {}", creds.server_url);
    println!("  • Auto-start:      Enabled (Restart=on-failure, NoNewPrivileges=true)");
    println!("\nAgent service is now active and polling for scheduled jobs.");
    println!("Check agent status at any time with: mailent agent status\n");

    Ok(())
}

fn run_start(system: bool) -> Result<(), String> {
    let mut cmd = Command::new("systemctl");
    if !system {
        cmd.arg("--user");
    }
    cmd.args(["start", "mailent-agent.service"]);
    let res = cmd
        .status()
        .map_err(|e| format!("Failed to run systemctl: {e}"))?;
    if res.success() {
        println!("Mailent agent service started.");
        Ok(())
    } else {
        Err("Failed to start mailent-agent.service via systemctl".to_string())
    }
}

fn run_stop(system: bool) -> Result<(), String> {
    let mut cmd = Command::new("systemctl");
    if !system {
        cmd.arg("--user");
    }
    cmd.args(["stop", "mailent-agent.service"]);
    let res = cmd
        .status()
        .map_err(|e| format!("Failed to run systemctl: {e}"))?;
    if res.success() {
        println!("Mailent agent service stopped.");
        Ok(())
    } else {
        Err("Failed to stop mailent-agent.service via systemctl".to_string())
    }
}

fn run_restart(system: bool) -> Result<(), String> {
    let mut cmd = Command::new("systemctl");
    if !system {
        cmd.arg("--user");
    }
    cmd.args(["restart", "mailent-agent.service"]);
    let res = cmd
        .status()
        .map_err(|e| format!("Failed to run systemctl: {e}"))?;
    if res.success() {
        println!("Mailent agent service restarted.");
        Ok(())
    } else {
        Err("Failed to restart mailent-agent.service via systemctl".to_string())
    }
}

fn run_uninstall(system: bool) -> Result<(), String> {
    let _ = run_stop(system);

    let mut disable_cmd = Command::new("systemctl");
    if !system {
        disable_cmd.arg("--user");
    }
    disable_cmd.args(["disable", "mailent-agent.service"]);
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

    println!("Mailent agent service uninstalled successfully.");
    Ok(())
}

async fn run_status(system: bool) -> Result<(), String> {
    let creds = load_credentials();

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║                  MAILENT AGENT STATUS                    ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // 1. Service state via systemctl
    let mut is_active_cmd = Command::new("systemctl");
    if !system {
        is_active_cmd.arg("--user");
    }
    is_active_cmd.args(["is-active", "mailent-agent.service"]);
    let service_state = match is_active_cmd.output() {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s == "active" {
                "Active (running)"
            } else if s == "inactive" {
                "Inactive (stopped)"
            } else {
                "Not loaded / stopped"
            }
        }
        Err(_) => "systemctl unavailable",
    };

    println!("  • Service State:     {}", service_state);
    println!(
        "  • Service Scope:     {}",
        if system { "system" } else { "user" }
    );

    // 2. Local credentials & Identity
    match &creds {
        Some(c) => {
            println!("  • Device Name:       {}", c.device_name);
            println!("  • Device ID:         {}", c.device_id);
            println!(
                "  • Organization:      {}",
                c.organization_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "Default".to_string())
            );
            println!("  • Control Plane:     {}", c.server_url);

            // 3. Query control plane for live agent telemetry
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

                        println!("  • Control Status:    Connected (authenticated)");
                        println!("  • Agent State:       {}", agent_status);
                        println!("  • Completed Jobs:    {}", completed_jobs);
                        println!("  • Last Heartbeat:    {}", last_heartbeat);
                    }
                }
                Ok(resp) => {
                    println!("  • Control Status:    Failed (HTTP {})", resp.status());
                }
                Err(e) => {
                    println!("  • Control Status:    Unreachable ({})", e);
                }
            }
        }
        None => {
            println!("  • Authentication:    Not configured (run 'mailent login' first)");
        }
    }
    println!();

    Ok(())
}

async fn run_daemon(poll_interval: u64, heartbeat_interval: u64) -> Result<(), String> {
    let creds = load_credentials().ok_or_else(|| {
        "This device is not linked to a Mailent workspace.\nPlease run 'mailent login' first to register this device.".to_string()
    })?;

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║             MAILENT SCANNING AGENT DAEMON                ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!(
        "  Device:        {} ({})",
        creds.device_name, creds.device_id
    );
    println!("  Control Plane: {}", creds.server_url);
    println!("  Poll Interval: {}s", poll_interval);
    println!("  Heartbeat:     {}s", heartbeat_interval);
    println!("  Capabilities:  [infrastructure_scan, active_verification]");
    println!("  PID:           {}", std::process::id());
    println!("\nListening for scheduled infrastructure scan jobs. Press Ctrl+C to terminate.\n");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let base_url = creds.server_url.trim_end_matches('/').to_string();
    let token = creds.device_token.clone();

    // 1. Initial Heartbeat
    send_heartbeat(&client, &base_url, &token, "idle").await;

    let mut last_heartbeat = Instant::now();
    let poll_dur = Duration::from_secs(poll_interval);
    let heartbeat_dur = Duration::from_secs(heartbeat_interval);

    loop {
        // Send heartbeat if interval elapsed
        if last_heartbeat.elapsed() >= heartbeat_dur {
            send_heartbeat(&client, &base_url, &token, "idle").await;
            last_heartbeat = Instant::now();
        }

        // Poll for assigned job
        let poll_url = format!("{base_url}/api/v1/agent/jobs/poll");
        let poll_resp = client
            .post(&poll_url)
            .header("Authorization", format!("Bearer {token}"))
            .json(&json!({}))
            .send()
            .await;

        match poll_resp {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(job_val) = body.get("job") {
                        if !job_val.is_null() {
                            if let Ok(job) = serde_json::from_value::<AgentJob>(job_val.clone()) {
                                println!("[*] Leased Job: {} (type: {:?})", job.id, job.job_type);
                                execute_job(&client, &base_url, &token, job).await;
                                last_heartbeat = Instant::now();
                                continue;
                            }
                        }
                    }
                }
            }
            Ok(resp) => {
                warn!("Job poll returned HTTP status: {}", resp.status());
            }
            Err(e) => {
                warn!("Failed to poll for jobs: {e}");
            }
        }

        tokio::time::sleep(poll_dur).await;
    }
}

async fn send_heartbeat(client: &reqwest::Client, base_url: &str, token: &str, status: &str) {
    let url = format!("{base_url}/api/v1/agent/heartbeat");
    let version = env!("CARGO_PKG_VERSION");
    let req_body = json!({
        "version": version,
        "capabilities": ["infrastructure_scan", "active_verification"],
        "status": status,
    });

    let _ = client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&req_body)
        .send()
        .await;
}

async fn execute_job(client: &reqwest::Client, base_url: &str, token: &str, job: AgentJob) {
    match job.job_type {
        AgentJobType::InfrastructureAssessment {
            domain,
            timeout_seconds,
        } => {
            println!(
                "  ↳ Executing infrastructure assessment for domain: {domain} (timeout: {timeout_seconds}s)"
            );

            let scanner_res = DomainScanner::new_live();
            let scanner = match scanner_res {
                Ok(s) => s,
                Err(e) => {
                    let err_msg = format!("Failed to initialize DomainScanner: {e}");
                    eprintln!("  [✗] {err_msg}");
                    report_failure(client, base_url, token, job.id, &err_msg).await;
                    return;
                }
            };

            match scanner.scan_domain(&domain).await {
                Ok(scan_result) => {
                    println!(
                        "  [✓] Scan completed for {domain}: {} endpoints checked, {} passed, Posture Grade: {}",
                        scan_result.endpoints_checked,
                        scan_result.endpoints_succeeded,
                        scan_result.assessment.posture_grade
                    );

                    let complete_url = format!("{base_url}/api/v1/agent/jobs/{}/complete", job.id);
                    let body = json!({
                        "assessment": scan_result.assessment,
                        "findings": scan_result.findings,
                        "assets": [],
                        "sessions": [],
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
                            println!("  [✓] Job {} reported completed to control plane", job.id);
                        }
                        Ok(resp) => {
                            eprintln!(
                                "  [!] Failed to report completion to control plane: HTTP {}",
                                resp.status()
                            );
                        }
                        Err(e) => {
                            eprintln!("  [!] Failed to report completion to control plane: {e}");
                        }
                    }
                }
                Err(e) => {
                    let err_msg = format!("Infrastructure scan failed: {e}");
                    eprintln!("  [✗] {err_msg}");
                    report_failure(client, base_url, token, job.id, &err_msg).await;
                }
            }
        }
        AgentJobType::ActiveVerification { endpoint } => {
            println!("  ↳ Active verification for endpoint: {endpoint}");
            let complete_url = format!("{base_url}/api/v1/agent/jobs/{}/complete", job.id);
            let _ = client
                .post(&complete_url)
                .header("Authorization", format!("Bearer {token}"))
                .json(&json!({
                    "output_summary": {
                        "endpoint": endpoint,
                        "verified": true,
                    }
                }))
                .send()
                .await;
            println!("  [✓] Active verification completed for {endpoint}");
        }
    }
}

async fn report_failure(
    client: &reqwest::Client,
    base_url: &str,
    token: &str,
    job_id: uuid::Uuid,
    error: &str,
) {
    let fail_url = format!("{base_url}/api/v1/agent/jobs/{job_id}/fail");
    let _ = client
        .post(&fail_url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "error": error }))
        .send()
        .await;
}
