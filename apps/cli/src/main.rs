#![allow(clippy::collapsible_if, clippy::too_many_arguments)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mailent_domain::{EmailSession, Finding};
use mailent_integrations::LiveDomainIntelligenceResolver;
use mailent_policy::PolicyPack;
use mailent_probe::ProbeLimits;
use mailent_scanner::{DomainScanner, DomainScannerConfig};
use time::OffsetDateTime;
use uuid::Uuid;

mod bridge;
mod companion;
mod credentials;
mod doctor;
pub mod engine;
mod fix;
mod installation;
mod monitor;

pub use engine::{locate_zeek, sync_assessment, validate_pcap, verified_zeek_version};

#[derive(Parser)]
#[command(
    name = "mailent",
    version,
    about = "Mailent — Email security from your terminal\nAnalyze captures, scan mail infrastructure, monitor live traffic, and remediate findings."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect this CLI installation to a Mailent workspace
    Login {
        /// Mailent server URL (default: http://localhost:8080)
        #[arg(long)]
        server: Option<String>,

        /// Friendly name for this device
        #[arg(long)]
        name: Option<String>,
    },

    /// Check authentication status and active organization
    Status {
        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Log out and revoke active device credentials
    Logout {
        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Analyze a local PCAP or PCAPNG capture file
    Analyze {
        /// Path to the PCAP or PCAPNG capture file
        capture: PathBuf,

        /// Output format: table (default) or json
        #[arg(short, long, default_value = "table", value_parser = ["table", "json"])]
        format: String,

        /// Directory to write generated reports into (default: current directory)
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,

        /// Path to Zeek executable (or zeek container runner)
        #[arg(long)]
        zeek: Option<PathBuf>,

        /// Enable packet checksum verification (disabled by default for offloaded captures)
        #[arg(long, default_value_t = false)]
        verify_checksums: bool,

        /// Skip writing report files to disk
        #[arg(long, default_value_t = false)]
        no_reports: bool,

        /// Sync assessment to Mailent organization workspace
        #[arg(long, default_value_t = false)]
        sync: bool,

        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Check mail servers, encryption, certificates, and DNS settings
    Scan {
        /// Target domain to scan (e.g. example.com)
        domain: String,

        /// Output format: table (default) or json
        #[arg(short, long, default_value = "table", value_parser = ["table", "json"])]
        format: String,

        /// Directory to write generated reports into (default: current directory)
        #[arg(short, long, default_value = ".")]
        output_dir: PathBuf,

        /// Connection timeout per endpoint in seconds
        #[arg(long, default_value_t = 5)]
        timeout: u64,

        /// Skip writing report files to disk
        #[arg(long, default_value_t = false)]
        no_reports: bool,

        /// Sync assessment to Mailent organization workspace
        #[arg(long, default_value_t = false)]
        sync: bool,

        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Manage live mail traffic with Zeek and send results to your workspace
    Monitor {
        /// Network interface that sees your mail-server traffic
        #[arg(short, long)]
        interface: String,
        /// Path to the required Zeek executable
        #[arg(long)]
        zeek: Option<PathBuf>,
    },

    /// Manage the local Mailent companion for workspace execution
    #[command(subcommand, hide = true)]
    Companion(companion::CompanionCommands),

    /// Run the local companion loopback bridge for browser acquisition
    Bridge {
        /// Local port for HTTP companion bridge
        #[arg(long, default_value_t = 15488)]
        port: u16,
    },

    /// Run system and connectivity diagnostics
    Doctor {
        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,
    },

    /// Safely remediate supported local mail server findings (e.g. TLS_LEGACY_VERSION)
    Fix {
        /// Target finding ID (UUID) or rule ID (e.g. TLS_LEGACY_VERSION, STARTTLS_MISSING)
        #[arg(default_value = "TLS_LEGACY_VERSION")]
        finding: String,

        /// Dry-run mode: show planned changes and verification steps without modifying configuration
        #[arg(long, default_value_t = false)]
        plan: bool,

        /// Target mail service (postfix, dovecot)
        #[arg(long)]
        service: Option<String>,

        /// Path to configuration file override (e.g. /etc/postfix/main.cf)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Target endpoint override for active verification (e.g. 127.0.0.1:25)
        #[arg(long)]
        target: Option<String>,

        /// Automatic confirmation (skip interactive prompt)
        #[arg(short, long, default_value_t = false)]
        yes: bool,

        /// Sync remediation record and active verification evidence to Mailent workspace
        #[arg(long, default_value_t = false)]
        sync: bool,

        /// Mailent server URL
        #[arg(long)]
        server: Option<String>,

        /// Revert configuration to a specified backup file
        #[arg(long)]
        rollback: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Login { server, name } => run_login(server, name).await,
        Commands::Status { server } => run_status(server).await,
        Commands::Logout { server } => run_logout(server).await,
        Commands::Analyze {
            capture,
            format,
            output_dir,
            zeek,
            verify_checksums,
            no_reports,
            sync,
            server,
        } => {
            run_analyze(
                capture,
                format,
                output_dir,
                zeek,
                verify_checksums,
                no_reports,
                sync,
                server,
            )
            .await
        }
        Commands::Scan {
            domain,
            format,
            output_dir,
            timeout,
            no_reports,
            sync,
            server,
        } => {
            run_scan(
                domain, format, output_dir, timeout, no_reports, sync, server,
            )
            .await
        }
        Commands::Monitor { interface, zeek } => monitor::run(interface, zeek).await,
        Commands::Companion(companion_cmd) => {
            companion::run_companion_command(companion_cmd).await
        }
        Commands::Bridge { port } => bridge::start_bridge_server(port).await,
        Commands::Doctor { server } => doctor::run_doctor(server).await,
        Commands::Fix {
            finding,
            plan,
            service,
            config,
            target,
            yes,
            sync,
            server,
            rollback,
        } => {
            fix::run_fix(
                finding, plan, service, config, target, yes, sync, server, rollback,
            )
            .await
        }
    };

    if let Err(err) = result {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

async fn run_analyze(
    capture_path: PathBuf,
    format: String,
    output_dir: PathBuf,
    zeek_override: Option<PathBuf>,
    verify_checksums: bool,
    no_reports: bool,
    sync: bool,
    server_override: Option<String>,
) -> Result<(), String> {
    let capture_name = capture_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("capture.pcap")
        .to_string();

    eprintln!("  [1/4] Validating capture file: {}", capture_name);
    let outcome = engine::execute_capture_analysis(engine::AnalysisOptions {
        capture_path: &capture_path,
        capture_name: Some(capture_name.clone()),
        title: None,
        zeek_override: zeek_override.as_deref(),
        verify_checksums,
        no_reports,
        output_dir: Some(&output_dir),
        sync,
        server_override,
    })
    .await?;

    eprintln!("  ✔ Analysis complete.\n");

    if format == "json" {
        let output = serde_json::json!({
            "assessment": outcome.assessment,
            "report_summary": {
                "report_id": outcome.report.metadata.report_id,
                "title": outcome.report.metadata.title,
                "posture_score": outcome.posture_score,
                "posture_grade": outcome.posture_grade,
                "risk_level": outcome.ai_risk_classification,
                "sessions_count": outcome.sessions.len(),
                "findings_count": outcome.findings.len(),
            },
            "written_reports": outcome.written_reports.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        print_capture_table(
            &capture_name,
            &outcome.capture_hash,
            outcome.file_size,
            &outcome.zeek_version,
            outcome.posture_score,
            &outcome.posture_grade,
            &outcome.ai_risk_classification,
            &outcome.ai_risk_rationale,
            &outcome.sessions,
            &outcome.findings,
            &outcome.written_reports,
            &outcome.warnings,
        );
    }

    Ok(())
}

async fn run_scan(
    raw_domain: String,
    format: String,
    output_dir: PathBuf,
    timeout_secs: u64,
    no_reports: bool,
    sync: bool,
    server_override: Option<String>,
) -> Result<(), String> {
    // Validate input before checking installed dependencies.
    let domain = mailent_scanner::normalize_scan_domain(&raw_domain).map_err(|e| e.to_string())?;
    let zeek_bin = locate_zeek(None)?;

    // 2. Initialize live scanner engine
    let resolver = LiveDomainIntelligenceResolver::new()
        .map_err(|e| format!("Failed to initialize live resolver: {e}"))?;

    let config = DomainScannerConfig {
        probe_limits: ProbeLimits {
            connect_timeout: Duration::from_secs(timeout_secs),
            read_timeout: Duration::from_secs(timeout_secs * 2),
            ..Default::default()
        },
        policy_pack: PolicyPack::modern(),
        sensor_hostname: "mailent-cli".to_string(),
        ..Default::default()
    };

    let scanner = DomainScanner::new(Arc::new(resolver), config);

    // 3. Execute domain scan
    let scan_result = scanner
        .scan_domain_with_progress(&domain, |event| match event {
            mailent_scanner::ScanProgressEvent::DiscoveringDns { domain } => {
                eprintln!("  [1/4] Discovering DNS records & mail servers for {domain}...");
            }
            mailent_scanner::ScanProgressEvent::DnsDiscovered { endpoints_count } => {
                eprintln!("        Discovered {endpoints_count} mail endpoint(s)");
            }
            mailent_scanner::ScanProgressEvent::FetchingPolicies => {
                eprintln!("  [2/4] Fetching MTA-STS and TLS-RPT policies...");
            }
            mailent_scanner::ScanProgressEvent::ProbingEndpoint {
                current,
                total,
                endpoint,
                service,
            } => {
                eprintln!("  [3/4] Probing endpoint [{current}/{total}] ({service} {endpoint})...");
            }
            mailent_scanner::ScanProgressEvent::AnalyzingPosture => {
                eprintln!("  [4/4] Computing cryptographic posture and generating reports...");
            }
            mailent_scanner::ScanProgressEvent::Complete => {
                eprintln!("  ✔ Scan completed successfully.\n");
            }
        })
        .await
        .map_err(|e| format!("Domain infrastructure scan failed: {e}"))?;

    // 4. Generate Report Files
    let mut written_reports = Vec::new();
    if !no_reports {
        std::fs::create_dir_all(&output_dir).map_err(|e| {
            format!(
                "Failed to create output directory {}: {e}",
                output_dir.display()
            )
        })?;

        let json_path = output_dir.join(format!("{domain}-report.json"));
        let json_content = mailent_reporting::to_json(&scan_result.report)
            .map_err(|e| format!("Failed to render report JSON: {e}"))?;
        std::fs::write(&json_path, json_content)
            .map_err(|e| format!("Failed to write {}: {e}", json_path.display()))?;
        written_reports.push(json_path);

        let html_path = output_dir.join(format!("{domain}-report.html"));
        let html_content = mailent_reporting::render_html(&scan_result.report)
            .map_err(|e| format!("Failed to render report HTML: {e}"))?;
        std::fs::write(&html_path, html_content)
            .map_err(|e| format!("Failed to write {}: {e}", html_path.display()))?;
        written_reports.push(html_path);

        let pdf_path = output_dir.join(format!("{domain}-report.pdf"));
        let pdf_bytes = mailent_reporting::render_pdf(&scan_result.report)
            .map_err(|e| format!("Failed to render report PDF: {e}"))?;
        std::fs::write(&pdf_path, pdf_bytes)
            .map_err(|e| format!("Failed to write {}: {e}", pdf_path.display()))?;
        written_reports.push(pdf_path);
    }

    // 5. Output formatted result
    if format == "json" {
        let output = serde_json::json!({
            "assessment": scan_result.assessment,
            "endpoints_checked": scan_result.endpoints_checked,
            "endpoints_succeeded": scan_result.endpoints_succeeded,
            "endpoints_failed": scan_result.endpoints_failed,
            "written_reports": written_reports.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
    } else {
        print_scan_table(&scan_result, &written_reports);
    }

    if sync {
        sync_assessment(
            server_override,
            &scan_result.assessment,
            &scan_result.findings,
            &[],
            &scan_result.sessions,
            Some(&zeek_bin),
        )
        .await?;
    }

    Ok(())
}


async fn run_login(
    server_override: Option<String>,
    name_override: Option<String>,
) -> Result<(), String> {
    let server_url = server_override
        .or_else(|| std::env::var("MAILENT_SERVER_URL").ok())
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "localhost".to_string());

    let device_name = name_override.unwrap_or_else(|| format!("Mailent CLI ({hostname})"));

    println!("Connecting Mailent CLI to {}", server_url);
    let client = reqwest::Client::new();
    let challenge_url = format!(
        "{}/api/v1/devices/authorize/challenge",
        server_url.trim_end_matches('/')
    );

    let challenge_req = serde_json::json!({
        "device_name": device_name,
        "hostname": hostname,
        "platform": std::env::consts::OS,
        "architecture": std::env::consts::ARCH,
    });

    let resp = client
        .post(&challenge_url)
        .json(&challenge_req)
        .send()
        .await
        .map_err(|e| format!("Failed to initiate authorization with {challenge_url}: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!("Challenge request failed (HTTP {status}): {text}"));
    }

    let challenge_data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse challenge response: {e}"))?;

    let code = challenge_data["code"]
        .as_str()
        .ok_or("Missing code in response")?;
    let verification_url = challenge_data["verification_url"]
        .as_str()
        .unwrap_or("/settings?tab=devices");
    let poll_interval = challenge_data["poll_interval_seconds"]
        .as_u64()
        .unwrap_or(2);

    let full_verify_url = if verification_url.starts_with("http") {
        verification_url.to_string()
    } else {
        format!("{}{}", server_url.trim_end_matches('/'), verification_url)
    };

    println!();
    println!("========================================================");
    println!("  Connection code: \x1b[1;36m{}\x1b[0m", code);
    println!(
        "  Approve in Mailent Workspace:    \x1b[4m{}\x1b[0m",
        full_verify_url
    );
    println!("========================================================");
    println!("Waiting for approval...");

    let poll_url = format!(
        "{}/api/v1/devices/authorize/poll",
        server_url.trim_end_matches('/')
    );
    let poll_req = serde_json::json!({ "code": code });

    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(900); // 15 minutes

    loop {
        if start_time.elapsed() > timeout {
            return Err("Authorization timed out. Please run `mailent login` again.".to_string());
        }

        tokio::time::sleep(Duration::from_secs(poll_interval)).await;

        let poll_resp = client.post(&poll_url).json(&poll_req).send().await;

        let poll_resp = match poll_resp {
            Ok(r) => r,
            Err(_) => continue,
        };

        if poll_resp.status() == reqwest::StatusCode::ACCEPTED {
            continue;
        }

        if poll_resp.status().is_success() {
            let data: serde_json::Value = poll_resp
                .json()
                .await
                .map_err(|e| format!("Failed to parse poll response: {e}"))?;

            if data["status"] == "approved" {
                let token = data["token"]
                    .as_str()
                    .ok_or("Missing token in approved response")?;
                let device_id_str = data["device_id"].as_str().unwrap_or_default();
                let device_id = Uuid::parse_str(device_id_str).unwrap_or_else(|_| Uuid::new_v4());
                let org_id = data["organization_id"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok());

                let creds = credentials::DeviceCredentials {
                    server_url: server_url.clone(),
                    device_id,
                    device_token: token.to_string(),
                    organization_id: org_id,
                    device_name: device_name.clone(),
                    created_at: OffsetDateTime::now_utc()
                        .format(&time::format_description::well_known::Rfc3339)
                        .unwrap_or_default(),
                };

                credentials::save_credentials(&creds)
                    .map_err(|e| format!("Failed to save credentials: {e}"))?;

                installation::report_best_effort(&creds, &server_url, None).await;
                println!();
                println!("\x1b[32m✔ Mailent installation connected!\x1b[0m");
                println!("  Device Name:     {}", creds.device_name);
                println!("  Device ID:       {}", creds.device_id);
                if let Some(oid) = creds.organization_id {
                    println!("  Organization ID: {}", oid);
                }
                println!(
                    "  Credentials:     {}",
                    credentials::credentials_path().display()
                );

                // Automatically install and start the background companion service on Linux
                if cfg!(target_os = "linux") {
                    match companion::auto_install_user_service() {
                        Ok(unit) => {
                            println!();
                            println!("\x1b[32m✔ Background companion service installed and started (systemd --user).\x1b[0m");
                            println!("  Service:         {}", unit.file_name().and_then(|n| n.to_str()).unwrap_or("mailent-companion.service"));
                            println!("  Local Bridge:    http://127.0.0.1:15488 (ready)");
                            println!("  Auto-start:      Enabled (restarts on failure and boots with user session)");
                            println!("\nYour workspace is now ready for local capture analysis and scans without keeping a terminal open.");
                        }
                        Err(e) => {
                            println!();
                            println!("[!] Could not auto-enable systemd user service: {e}");
                            println!("    To start the companion service manually:");
                            println!("      mailent companion start");
                            println!("    Or run in foreground for debugging:");
                            println!("      mailent companion run");
                        }
                    }
                } else {
                    println!();
                    println!("To enable local workspace acquisition, run:");
                    println!("  mailent companion run");
                }

                return Ok(());
            }
        } else {
            let text = poll_resp.text().await.unwrap_or_default();
            return Err(format!("Authorization failed: {text}"));
        }
    }
}

async fn run_status(server_override: Option<String>) -> Result<(), String> {
    let creds = match credentials::load_credentials() {
        Some(c) => c,
        None => {
            println!("Status: Not authenticated");
            println!(
                "No credentials found at {}",
                credentials::credentials_path().display()
            );
            println!("Run `mailent login` to register this device.");
            return Ok(());
        }
    };

    let server_url = server_override
        .or_else(|| std::env::var("MAILENT_SERVER_URL").ok())
        .unwrap_or(creds.server_url.clone());

    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/devices/status", server_url.trim_end_matches('/'));

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", creds.device_token))
        .send()
        .await
        .map_err(|e| format!("Failed to connect to {url}: {e}"))?;

    if credentials::handle_rejection(resp.status(), &creds)? {
        println!("Status: Unauthorized / Token Revoked");
        println!(
            "Device credentials at {} are invalid or revoked.",
            credentials::credentials_path().display()
        );
        println!("Run `mailent login` to re-authorize this device.");
        return Ok(());
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Server returned HTTP {status}: {body}"));
    }

    let status_data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| format!("Failed to parse status response: {e}"))?;

    installation::report_best_effort(&creds, &server_url, None).await;
    println!("Mailent CLI Status");
    println!("------------------");
    println!("Workspace Link:  \x1b[32mConnected (authenticated)\x1b[0m");
    println!("Server:          {}", server_url);
    println!("Device Name:     {}", creds.device_name);
    println!("Device ID:       {}", creds.device_id);
    if let Some(org) = status_data.get("organization") {
        let org_name = org["name"].as_str().unwrap_or("Unknown");
        let org_id = org["id"].as_str().unwrap_or("Unknown");
        println!("Organization:    {} ({})", org_name, org_id);
    }
    println!(
        "Credentials:     {}",
        credentials::credentials_path().display()
    );

    let service_state = companion::check_service_state(false);
    println!("Companion (svc): {}", service_state);

    let (bridge_ready, _) = companion::check_bridge_readiness(15488).await;
    if bridge_ready {
        println!("Loopback Bridge: \x1b[32mReady (http://127.0.0.1:15488)\x1b[0m");
    } else {
        println!("Loopback Bridge: \x1b[33mNot responding (port 15488)\x1b[0m");
    }

    match crate::engine::locate_zeek(None) {
        Ok(zeek_path) => {
            println!("Zeek 8+:         \x1b[32mReady ({})\x1b[0m", zeek_path.display());
        }
        Err(e) => {
            println!("Zeek 8+:         \x1b[31m{}\x1b[0m", e);
        }
    }

    Ok(())
}

async fn run_logout(server_override: Option<String>) -> Result<(), String> {
    let creds = match credentials::load_credentials() {
        Some(c) => c,
        None => {
            println!("Not logged in.");
            return Ok(());
        }
    };

    let server_url = server_override
        .or_else(|| std::env::var("MAILENT_SERVER_URL").ok())
        .unwrap_or(creds.server_url.clone());

    let client = reqwest::Client::new();
    let url = format!("{}/api/v1/devices/logout", server_url.trim_end_matches('/'));

    let _ = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", creds.device_token))
        .send()
        .await;

    credentials::clear_credentials()
        .map_err(|e| format!("Failed to remove credentials file: {e}"))?;

    println!("\x1b[32m✔ Logged out successfully. Local credentials removed.\x1b[0m");
    Ok(())
}

fn print_capture_table(
    capture_name: &str,
    capture_hash: &str,
    size_bytes: u64,
    zeek_version: &str,
    posture_score: f32,
    posture_grade: &str,
    risk_level: &str,
    risk_rationale: &str,
    sessions: &[EmailSession],
    findings: &[Finding],
    reports: &[PathBuf],
    warnings: &[String],
) {
    println!("\n╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║                   MAILENT CAPTURE ANALYSIS                               ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!("  Capture:       {}", capture_name);
    println!("  SHA-256:       {}", capture_hash);
    println!(
        "  Size:          {:.2} KiB ({} bytes)",
        size_bytes as f64 / 1024.0,
        size_bytes
    );
    println!("  Analyzer:      {}", zeek_version);
    println!();
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ SECURITY POSTURE & RISK VERDICT                                            │");
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    println!("  Score:         {:.1} / 100", posture_score);
    println!("  Grade:         {}", posture_grade);
    println!("  Risk Level:    {}", risk_level);
    println!("  Verdict:       {}", risk_rationale);
    println!();
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│ RECONSTRUCTED EMAIL SESSIONS ({} found)                                    │",
        sessions.len()
    );
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    if sessions.is_empty() {
        println!("  No email sessions identified in capture.");
    }
    for (i, s) in sessions.iter().enumerate() {
        println!(
            "  [{}] {:?} | {} -> {}",
            i + 1,
            s.protocol,
            s.flow.src_ip,
            s.flow.dst_ip
        );
        if let Some(st) = &s.starttls_state {
            println!("      STARTTLS:        {:?}", st);
        }
        if let Some(v) = &s.tls_version {
            println!("      TLS Version:     {}", v);
        }
        if let Some(c) = &s.cipher_suite {
            println!("      Cipher Suite:    {}", c.name);
        }
        if let Some(ke) = &s.key_exchange {
            println!("      Key Exchange:    {:?}", ke);
        }
        if let Some(cert) = &s.certificate {
            println!("      Certificate:     CN={}", cert.reference.subject);
            println!("      Issuer:          {}", cert.reference.issuer);
            println!(
                "      Validity:        {} -> {}",
                cert.validity.not_before, cert.validity.not_after
            );
        }
    }
    println!();
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│ POLICY & CRYPTOGRAPHIC FINDINGS ({} identified)                            │",
        findings.len()
    );
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    if findings.is_empty() {
        println!("  No cryptographic or policy non-compliances detected.");
    }
    for f in findings {
        println!("  • [{}] {} (rule: {})", f.severity, f.title, f.rule_id);
        println!("    {}", f.description);
        println!("    Remediation: {}", f.remediation);
    }
    println!();
    if !warnings.is_empty() {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!("│ EVIDENCE GAPS & WARNINGS                                                   │");
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for w in warnings {
            println!("  ! {}", w);
        }
        println!();
    }
    if !reports.is_empty() {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!("│ EXPORTED SECURITY REPORTS                                                  │");
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for r in reports {
            println!("  -> {}", r.display());
        }
        println!();
    }
    println!("══════════════════════════════════════════════════════════════════════════════\n");
}

fn print_scan_table(result: &mailent_scanner::InfrastructureScanResult, reports: &[PathBuf]) {
    let report = &result.report;
    let infra = report.infrastructure.as_ref();

    println!("\n╔════════════════════════════════════════════════════════════════════════════╗");
    println!("║                MAILENT DOMAIN INFRASTRUCTURE ASSESSMENT                    ║");
    println!("╚════════════════════════════════════════════════════════════════════════════╝");
    println!(
        "  Domain:        {}",
        report
            .metadata
            .target_domain
            .as_deref()
            .unwrap_or("unknown")
    );
    println!(
        "  Endpoints:     {} checked ({} succeeded, {} failed/unreachable)",
        result.endpoints_checked, result.endpoints_succeeded, result.endpoints_failed
    );
    if let Some(inf) = infra {
        println!("  DNSSEC:        {}", inf.dnssec_status);
        println!(
            "  MTA-STS:       {}",
            inf.mta_sts_mode.as_deref().unwrap_or("Not published")
        );
        if let Some(details) = &inf.mta_sts_policy_details {
            println!("                 ({})", details);
        }
        println!(
            "  TLS-RPT:       {}",
            inf.tls_rpt_destination
                .as_deref()
                .unwrap_or("Not published")
        );
    }
    println!();
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!("│ SECURITY POSTURE & RISK VERDICT                                            │");
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    if let Some(p) = &report.posture {
        println!("  Score:         {:.1} / 100", p.score);
        println!("  Grade:         {}", p.grade);
    }
    println!(
        "  Risk Level:    {}",
        result.assessment.ai_risk_classification
    );
    println!("  Verdict:       {}", result.assessment.ai_risk_rationale);
    println!();
    if let Some(inf) = infra {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!(
            "│ DISCOVERED ENDPOINTS & ACTIVE PROBE RESULTS ({} total)                      │",
            inf.discovered_endpoints.len()
        );
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for ep in &inf.discovered_endpoints {
            println!(
                "  [{}] {}:{} (priority: {})",
                ep.service,
                ep.host,
                ep.port,
                ep.priority
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "n/a".into())
            );
            if !ep.resolved_ips.is_empty() {
                println!("      IP Addresses:    {}", ep.resolved_ips.join(", "));
            }
            println!("      STARTTLS:        {}", ep.starttls_status);
            if let Some(tls) = &ep.tls_version {
                println!("      TLS Version:     {}", tls);
            }
            if let Some(c) = &ep.cipher {
                println!("      Cipher Suite:    {}", c);
            }
            if let Some(sub) = &ep.cert_subject {
                println!("      Certificate:     CN={}", sub);
            }
            if let Some(val) = &ep.cert_validity {
                println!("      Validity:        {}", val);
            }
            println!("      DANE Status:     {}", ep.dane_status);
        }
        println!();
    }
    println!("┌────────────────────────────────────────────────────────────────────────────┐");
    println!(
        "│ POLICY & INFRASTRUCTURE FINDINGS ({} identified)                           │",
        report.findings.len()
    );
    println!("├────────────────────────────────────────────────────────────────────────────┤");
    if report.findings.is_empty() {
        println!("  No policy violations detected.");
    }
    for f in &report.findings {
        println!("  • [{}] {} (rule: {})", f.severity, f.title, f.rule_id);
        println!("    {}", f.description);
    }
    if !report.remediation.is_empty() {
        println!();
        println!("  Remediation Guidance:");
        for rem in &report.remediation {
            println!("  • {}", rem.title);
            println!("    {}", rem.recommendation);
        }
    }
    println!();
    if !report.evidence_gaps.is_empty() {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!("│ COVERAGE GAPS & WARNINGS                                                   │");
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for g in &report.evidence_gaps {
            println!("  ! {}", g);
        }
        println!();
    }
    if !reports.is_empty() {
        println!("┌────────────────────────────────────────────────────────────────────────────┐");
        println!("│ EXPORTED SECURITY REPORTS                                                  │");
        println!("├────────────────────────────────────────────────────────────────────────────┤");
        for r in reports {
            println!("  -> {}", r.display());
        }
        println!();
    }
    println!("══════════════════════════════════════════════════════════════════════════════\n");
}
