use std::process::Command;

#[test]
fn test_cli_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .arg("--help")
        .output()
        .expect("Failed to execute mailent --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Analyze captures, scan mail infrastructure, monitor live traffic, and remediate findings.")
    );
    assert!(stdout.contains("analyze"));
    assert!(stdout.contains("scan"));
    assert!(stdout.contains("fix"));
}

#[test]
fn test_cli_analyze_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args(["analyze", "--help"])
        .output()
        .expect("Failed to execute mailent analyze --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Analyze a local PCAP or PCAPNG capture file"));
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--output-dir"));
    assert!(stdout.contains("--zeek"));
}

#[test]
fn test_cli_scan_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args(["scan", "--help"])
        .output()
        .expect("Failed to execute mailent scan --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Check mail servers, encryption, certificates, and DNS settings"));
    assert!(stdout.contains("--format"));
    assert!(stdout.contains("--timeout"));
}

#[test]
fn test_cli_analyze_invalid_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args(["analyze", "nonexistent.pcap"])
        .output()
        .expect("Failed to execute mailent");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Capture file does not exist"));
}

#[test]
fn test_cli_analyze_invalid_magic() {
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args(["analyze", "Cargo.toml"])
        .output()
        .expect("Failed to execute mailent");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a valid PCAP or PCAPNG packet capture"));
}

#[test]
fn test_cli_scan_invalid_domain() {
    for bad in [
        "invalid domain with spaces",
        "example.com&test=1",
        "<script>.com",
        "bad-suffix-.com",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
            .args(["scan", bad])
            .output()
            .expect("Failed to execute mailent");

        assert!(!output.status.success(), "Bad domain '{}' should fail", bad);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Invalid domain format") || stderr.contains("invalid target domain"),
            "Expected domain validation failure for '{bad}', got: {stderr}"
        );
    }
}

fn fixture(name: &str) -> std::path::PathBuf {
    let c1 = std::path::Path::new("fixtures/pcap").join(name);
    if c1.exists() {
        return c1;
    }
    let c2 = std::path::Path::new("../../fixtures/pcap").join(name);
    if c2.exists() {
        return c2;
    }
    std::path::PathBuf::from(name)
}

fn edge_fixture(name: &str) -> std::path::PathBuf {
    let c1 = std::path::Path::new("fixtures/pcap_edge").join(name);
    if c1.exists() {
        return c1;
    }
    let c2 = std::path::Path::new("../../fixtures/pcap_edge").join(name);
    if c2.exists() {
        return c2;
    }
    std::path::PathBuf::from(name)
}

#[test]
fn test_cli_analyze_real_pcap_json() {
    let pcap = fixture("smtp_starttls.pcap");
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--format",
            "json",
            "--no-reports",
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output must be valid JSON");
    assert_eq!(
        parsed["assessment"]["source"]["capture_name"],
        "smtp_starttls.pcap"
    );
    assert_eq!(parsed["report_summary"]["risk_level"], "HIGH");
}

#[test]
fn test_cli_analyze_downgrade_auth_exposed() {
    let pcap = edge_fixture("smtp_downgrade_auth_exposed.pcap");
    if !pcap.exists() {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--format",
            "json",
            "--no-reports",
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output must be valid JSON");
    assert_eq!(parsed["report_summary"]["findings_count"], 1);
    assert_eq!(parsed["report_summary"]["risk_level"], "HIGH");
    assert_eq!(
        parsed["assessment"]["finding_ids"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_cli_analyze_imap_tls13_identifies_imaps() {
    let pcap = fixture("imap_tls13.pcap");
    if !pcap.exists() {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--format",
            "json",
            "--no-reports",
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output must be valid JSON");
    let protos = parsed["assessment"]["protocols_identified"]
        .as_array()
        .unwrap();
    assert!(
        protos.iter().any(|p| p.as_str().unwrap().contains("IMAPS")),
        "Expected IMAPS in protocols_identified, got: {protos:?}"
    );
}

#[test]
fn test_cli_analyze_corrupted_packet_rejected() {
    let pcap = edge_fixture("corrupted_packet_len.pcap");
    if !pcap.exists() {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--format",
            "json",
            "--no-reports",
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("truncated dump") || stderr.contains("failed to read a packet"));
}

#[test]
fn test_cli_analyze_generates_json_html_pdf_reports() {
    let pcap = fixture("smtp_starttls.pcap");
    let temp_dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--output-dir",
            temp_dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(output.status.success());
    let files: Vec<_> = std::fs::read_dir(temp_dir.path())
        .unwrap()
        .map(|r| r.unwrap().file_name().into_string().unwrap())
        .collect();

    assert!(
        files.iter().any(|f| f.ends_with(".json")),
        "Missing JSON report: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with(".html")),
        "Missing HTML report: {files:?}"
    );
    assert!(
        files.iter().any(|f| f.ends_with(".pdf")),
        "Missing PDF report: {files:?}"
    );

    for file_name in &files {
        let content = std::fs::read(temp_dir.path().join(file_name)).unwrap();
        assert!(
            !content.is_empty(),
            "Report file {} should not be empty",
            file_name
        );
        if file_name.ends_with(".pdf") {
            assert!(content.starts_with(b"%PDF-"), "PDF must have %PDF- header");
        } else if file_name.ends_with(".html") {
            let html_str = String::from_utf8_lossy(&content);
            assert!(
                html_str.contains("<!DOCTYPE html>"),
                "HTML must have doctype"
            );
            assert!(html_str.contains("MAILENT"), "HTML must have Mailent brand");
        }
    }
}

#[test]
fn test_cli_analyze_ipv6_smtp() {
    let pcap = edge_fixture("ipv6_smtp.pcap");
    if !pcap.exists() {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--format",
            "json",
            "--no-reports",
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output must be valid JSON");
    assert_eq!(
        parsed["assessment"]["source"]["capture_name"],
        "ipv6_smtp.pcap"
    );
    let protos = parsed["assessment"]["protocols_identified"]
        .as_array()
        .unwrap();
    assert!(
        protos.iter().any(|p| p.as_str().unwrap().contains("SMTP")),
        "Expected SMTP in protocols_identified, got: {protos:?}"
    );
}

#[test]
fn test_cli_analyze_vlan_tagged() {
    let pcap = edge_fixture("vlan_tagged_smtp.pcap");
    if !pcap.exists() {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--format",
            "json",
            "--no-reports",
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output must be valid JSON");
    assert_eq!(
        parsed["assessment"]["source"]["capture_name"],
        "vlan_tagged_smtp.pcap"
    );
}

#[test]
fn test_cli_analyze_non_mail_rejected() {
    let pcap = edge_fixture("non_mail_http_on_port_25.pcap");
    if !pcap.exists() {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--format",
            "json",
            "--no-reports",
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No email connections were found")
            || stderr.contains("No email sessions found"),
        "Expected no email connections found message, got: {stderr}"
    );
}

#[test]
fn test_cli_analyze_pop3_stls_rejected() {
    let pcap = edge_fixture("pop3_stls_rejected.pcap");
    if !pcap.exists() {
        return;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "analyze",
            pcap.to_str().unwrap(),
            "--format",
            "json",
            "--no-reports",
        ])
        .output()
        .expect("Failed to execute mailent");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("Output must be valid JSON");
    let protos = parsed["assessment"]["protocols_identified"]
        .as_array()
        .unwrap();
    assert!(
        protos.iter().any(|p| p.as_str().unwrap().contains("POP3")),
        "Expected POP3 in protocols_identified, got: {protos:?}"
    );
}
