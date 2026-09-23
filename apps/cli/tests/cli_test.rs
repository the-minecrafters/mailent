use std::process::Command;

#[test]
fn test_cli_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .arg("--help")
        .output()
        .expect("Failed to execute mailent --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Analyze local captures or actively scan domain mail infrastructure"));
    assert!(stdout.contains("analyze"));
    assert!(stdout.contains("scan"));
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
    assert!(stdout.contains("Actively scan and assess domain mail infrastructure"));
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
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args(["scan", "invalid domain with spaces"])
        .output()
        .expect("Failed to execute mailent");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid domain format"));
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
    assert_eq!(parsed["report_summary"]["risk_level"], "MEDIUM");
}
