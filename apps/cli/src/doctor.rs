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
            println!("[•] Sign-in saved; checking workspace access…");
            println!("    • Installation:     {}", c.device_name);
            println!("    • Device ID:       {}", c.device_id);
            println!(
                "    • Organization:    {}",
                c.organization_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "None".to_string())
            );
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
    print!("[*] Checking workspace connectivity ({})... ", server_url);
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
                "\r[✓] Workspace reachable at {} ({} ms)",
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
                        println!("    • Workspace connection verified");
                    }
                    Ok(dev_resp) => {
                        if let Some(c) = &creds {
                            crate::credentials::handle_rejection(dev_resp.status(), c)?;
                        }
                        println!(
                            "    [!] Workspace access rejected (HTTP {})",
                            dev_resp.status()
                        );
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
                "\r[!] Workspace returned HTTP {} from {}",
                resp.status(),
                health_url
            );
            all_ok = false;
        }
        Err(e) => {
            println!("\r[✗] Unable to reach workspace at {}: {}", server_url, e);
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

    // Zeek is a required product dependency, not an optional diagnostic.
    match crate::locate_zeek(None) {
        Ok(path) => println!("[✓] Required Zeek 8+: {}", path.display()),
        Err(error) => {
            println!("[✗] {error}");
            all_ok = false;
        }
    }

    if let Some(creds) = &creds {
        crate::installation::report_best_effort(creds, &server_url, None).await;
    }

    println!("\n------------------------------------------------------------");
    if all_ok {
        println!(
            "Status: Required dependencies are ready. Mail-server reachability depends on this network."
        );
    } else {
        println!("Status: Diagnostics completed with warnings/issues above.");
    }
    println!("------------------------------------------------------------\n");

    if all_ok {
        Ok(())
    } else {
        Err("Setup is incomplete. Resolve the checks above and run 'mailent doctor' again.".into())
    }
}
