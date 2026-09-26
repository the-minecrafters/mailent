use std::process::Command;
use std::time::Instant;

use crate::credentials::{credentials_path, load_credentials};

pub async fn run_doctor(server_override: Option<String>) -> Result<(), String> {
    println!("\n── 󰙨 Mailent System Diagnostics (Doctor) ──\n");

    let mut all_ok = true;

    // 1. Operating System and Architecture
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    println!("  󰄬 Platform:     {} ({})", os, arch);

    // 2. Credentials and Device Identity
    let creds = load_credentials();
    let server_url = server_override
        .or_else(|| creds.as_ref().map(|c| c.server_url.clone()))
        .unwrap_or_else(|| "http://localhost:8080".to_string());

    let token_opt = match &creds {
        Some(c) => {
            println!("  󰒍 Identity:     {} ({})", c.device_name, c.device_id);
            if let Some(oid) = c.organization_id {
                println!("  󰞀 Organization: {}", oid);
            }
            println!("  󰈙 Config File:  {}", credentials_path().display());
            Some(c.device_token.clone())
        }
        None => {
            println!("  󰀦 Authentication: Not configured (run 'mailent login' to link device)");
            None
        }
    };

    // 3. Control Plane Connectivity
    print!("  󱐋 Workspace:    Connecting to {}… ", server_url);
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
                "\r  󰄬 Workspace:    Reachable at {} ({} ms)",
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
                        println!("  󰄬 Token Check:  Workspace connection verified");
                    }
                    Ok(dev_resp) => {
                        if let Some(c) = &creds {
                            crate::credentials::handle_rejection(dev_resp.status(), c)?;
                        }
                        println!(
                            "  󰀦 Token Check:  Workspace access rejected (HTTP {})",
                            dev_resp.status()
                        );
                        all_ok = false;
                    }
                    Err(e) => {
                        println!("  󰀦 Token Check:  Failed to verify device token: {e}");
                        all_ok = false;
                    }
                }
            }
        }
        Ok(resp) => {
            println!(
                "\r  󰅖 Workspace:    Returned HTTP {} from {}",
                resp.status(),
                health_url
            );
            all_ok = false;
        }
        Err(e) => {
            println!("\r  󰅖 Workspace:    Unable to reach {} ({})", server_url, e);
            all_ok = false;
        }
    }

    // 4. DNS Resolution Test
    match tokio::net::lookup_host("smtp.gmail.com:25").await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                println!(
                    "  󰄬 DNS Resolver: Operational (resolved smtp.gmail.com -> {})",
                    addr.ip()
                );
            } else {
                println!("  󰀦 DNS Resolver: Returned no addresses");
            }
        }
        Err(e) => {
            println!("  󰀦 DNS Resolver: Warning: {}", e);
        }
    }

    // 5. OpenSSL / Crypto Libraries
    match Command::new("openssl").arg("version").output() {
        Ok(output) if output.status.success() => {
            let ver = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("  󰌆 Cryptography: {}", ver);
        }
        _ => {
            println!("  󰌆 Cryptography: Built-in Rustls / native TLS provider");
        }
    }

    // Zeek is a required product dependency, not an optional diagnostic.
    match crate::locate_zeek(None) {
        Ok(path) => println!("  󰏗 Zeek 8+:      {}", path.display()),
        Err(error) => {
            println!("  󰅖 Zeek 8+:      {error}");
            all_ok = false;
        }
    }

    // Companion service state
    let service_state = crate::companion::check_service_state(false);
    println!("  󱐋 Companion:    {} (systemd --user)", service_state);

    // Local loopback bridge check
    let (bridge_ready, _) = crate::companion::check_bridge_readiness(15488).await;
    if bridge_ready {
        println!("  󰒋 Loopback:     Ready on http://127.0.0.1:15488");
    } else {
        println!("  󰒋 Loopback:     Offline (mailent companion start)");
    }

    if let Some(creds) = &creds {
        crate::installation::report_best_effort(creds, &server_url, None).await;
    }

    println!();
    if all_ok {
        println!("  󰄬 Status: All required system diagnostics passed.");
    } else {
        println!("  󰀦 Status: Diagnostics completed with warnings/issues above.");
    }
    println!();

    if all_ok {
        Ok(())
    } else {
        Err("Setup is incomplete. Resolve the checks above and run 'mailent doctor' again.".into())
    }
}
