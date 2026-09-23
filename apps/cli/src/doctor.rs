use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use crate::credentials::{credentials_path, load_credentials};

pub async fn run_doctor(server_override: Option<String>) -> Result<(), String> {
    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║             MAILENT SYSTEM DIAGNOSTICS (DOCTOR)          ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    let mut all_ok = true;

    // 1. Operating System and Architecture
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    println!("[✓] Platform: {} ({})", os, arch);

    // 2. Credentials and Device Identity
    let creds = load_credentials();
    let server_url = server_override
        .or_else(|| creds.as_ref().map(|c| c.server_url.clone()))
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let token_opt = match &creds {
        Some(c) => {
            let masked_token = if c.device_token.len() > 8 {
                format!("{}...", &c.device_token[..8])
            } else {
                "***".to_string()
            };
            println!("[✓] Authentication: Authenticated");
            println!("    • Device Name:     {}", c.device_name);
            println!("    • Device ID:       {}", c.device_id);
            println!(
                "    • Organization:    {}",
                c.organization_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "None".to_string())
            );
            println!("    • Token:           {}", masked_token);
            println!("    • Config File:     {}", credentials_path().display());
            Some(c.device_token.clone())
        }
        None => {
            println!("[!] Authentication: Not configured");
            println!("    Notice: Run 'mailent login' to link this device to an organization.");
            None
        }
    };

    // 3. Control Plane Connectivity
    print!(
        "[*] Checking control plane connectivity ({})... ",
        server_url
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    let start = Instant::now();
    let health_url = format!("{}/health", server_url.trim_end_matches('/'));
    match client.get(&health_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let elapsed = start.elapsed();
            println!(
                "\r[✓] Control plane reachable at {} ({} ms)",
                server_url,
                elapsed.as_millis()
            );

            if let Some(token) = token_opt {
                let status_url =
                    format!("{}/api/v1/devices/status", server_url.trim_end_matches('/'));
                match client
                    .get(&status_url)
                    .header("Authorization", format!("Bearer {token}"))
                    .send()
                    .await
                {
                    Ok(dev_resp) if dev_resp.status().is_success() => {
                        println!("    • Device token verified with control plane");
                    }
                    Ok(dev_resp) => {
                        println!("    [!] Device token rejected (HTTP {})", dev_resp.status());
                        all_ok = false;
                    }
                    Err(e) => {
                        println!("    [!] Failed to verify device token: {e}");
                        all_ok = false;
                    }
                }
            }
        }
        Ok(resp) => {
            println!(
                "\r[!] Control plane returned HTTP {} from {}",
                resp.status(),
                health_url
            );
            all_ok = false;
        }
        Err(e) => {
            println!(
                "\r[✗] Unable to reach control plane at {}: {}",
                server_url, e
            );
            println!("    Notice: Make sure the Mailent server is running.");
            all_ok = false;
        }
    }

    // 4. DNS Resolution Test
    print!("[*] Testing DNS resolution... ");
    match tokio::net::lookup_host("smtp.gmail.com:25").await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                println!(
                    "\r[✓] DNS resolution operational (resolved smtp.gmail.com -> {})",
                    addr.ip()
                );
            } else {
                println!("\r[!] DNS resolution returned no addresses");
            }
        }
        Err(e) => {
            println!("\r[!] DNS resolution warning: {}", e);
        }
    }

    // 5. OpenSSL / Crypto Libraries
    match Command::new("openssl").arg("version").output() {
        Ok(output) if output.status.success() => {
            let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("[✓] TLS Cryptography: {}", ver);
        }
        _ => {
            println!("[✓] TLS Cryptography: Built-in Rustls / native TLS provider");
        }
    }

    // 6. Zeek Forensics Engine Detection
    let zeek_detected = check_zeek();
    if let Some(zeek_ver) = zeek_detected {
        println!("[✓] Zeek Network Security Monitor: {}", zeek_ver);
        println!("    • Local PCAP deep protocol inspection is ENABLED");
    } else {
        println!("[!] Zeek Network Security Monitor: Not found in PATH");
        println!(
            "    ℹ Note: Zeek is only required for local offline PCAP file analysis (`mailent analyze`)."
        );
        println!("    ℹ Domain infrastructure scanning (`mailent scan`), scheduled monitoring,");
        println!("      and agent execution do NOT require Zeek and are 100% operational.");
    }

    // 7. Systemd Service Status
    let systemctl_avail = Command::new("systemctl").arg("--version").output().is_ok();
    if systemctl_avail {
        let is_active = Command::new("systemctl")
            .args(["--user", "is-active", "mailent-agent.service"])
            .output();

        match is_active {
            Ok(out) => {
                let status_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if status_str == "active" {
                    println!("[✓] Mailent Agent Service: Active (running via systemd --user)");
                } else if status_str == "inactive" {
                    println!(
                        "[•] Mailent Agent Service: Installed but inactive (start with 'mailent agent start')"
                    );
                } else {
                    // Try checking system level
                    let is_sys_active = Command::new("systemctl")
                        .args(["is-active", "mailent-agent.service"])
                        .output();
                    if let Ok(sys_out) = is_sys_active {
                        let sys_status =
                            String::from_utf8_lossy(&sys_out.stdout).trim().to_string();
                        if sys_status == "active" {
                            println!(
                                "[✓] Mailent Agent Service: Active (running via systemd system service)"
                            );
                        } else {
                            println!(
                                "[•] Mailent Agent Service: Not installed (install with 'mailent agent install')"
                            );
                        }
                    } else {
                        println!(
                            "[•] Mailent Agent Service: Not installed (install with 'mailent agent install')"
                        );
                    }
                }
            }
            Err(_) => {
                println!("[•] Mailent Agent Service: Not installed");
            }
        }
    } else {
        println!(
            "[•] Service Manager: systemctl not available (direct foreground mode available via 'mailent agent run')"
        );
    }

    println!("\n------------------------------------------------------------");
    if all_ok {
        println!("Status: System ready for scanning and agent execution.");
    } else {
        println!("Status: Diagnostics completed with warnings/issues above.");
    }
    println!("------------------------------------------------------------\n");

    Ok(())
}

fn check_zeek() -> Option<String> {
    if let Ok(z) = std::env::var("MAILENT_ZEEK") {
        let p = PathBuf::from(z);
        if p.exists() {
            if let Ok(out) = Command::new(&p).arg("--version").output() {
                if out.status.success() {
                    return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
                }
            }
            return Some(p.display().to_string());
        }
    }

    for bin in ["zeek", "zeek-container"] {
        if let Ok(out) = Command::new(bin).arg("--version").output() {
            if out.status.success() {
                return Some(String::from_utf8_lossy(&out.stdout).trim().to_string());
            }
        }
    }

    None
}
