use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_fix_help() {
    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args(["fix", "--help"])
        .output()
        .expect("Failed to execute mailent fix --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Safely remediate supported local mail server findings"));
    assert!(stdout.contains("--plan"));
    assert!(stdout.contains("--service"));
    assert!(stdout.contains("--config"));
    assert!(stdout.contains("--target"));
    assert!(stdout.contains("--yes"));
    assert!(stdout.contains("--sync"));
    assert!(stdout.contains("--server"));
    assert!(stdout.contains("--rollback"));
}

#[test]
fn test_cli_fix_plan_tls_legacy_version_postfix() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("main.cf");
    let initial_content = "myhostname = mail.example.com\nsmtpd_tls_protocols = !SSLv2, !SSLv3\nsmtpd_tls_mandatory_protocols = !SSLv2, !SSLv3\n";
    fs::write(&config_path, initial_content).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "fix",
            "TLS_LEGACY_VERSION",
            "--plan",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute mailent fix --plan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Mailent Remediation Plan"));
    assert!(stdout.contains("Deprecated TLS Version Negotiated"));
    assert!(stdout.contains("smtpd_tls_protocols"));
    assert!(stdout.contains(">=TLSv1.2, !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"));
    assert!(stdout.contains("smtpd_tls_mandatory_protocols"));
    assert!(stdout.contains("postfix check"));
    assert!(stdout.contains("postfix reload"));

    // Verify dry-run: config file must NOT have changed
    let current_content = fs::read_to_string(&config_path).unwrap();
    assert_eq!(current_content, initial_content);
}

#[test]
fn test_cli_fix_plan_starttls_missing_guided_when_certs_missing() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("main.cf");
    // No certs configured or cert paths don't exist
    let initial_content = "myhostname = mail.example.com\nsmtpd_tls_security_level = none\n";
    fs::write(&config_path, initial_content).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "fix",
            "STARTTLS_MISSING",
            "--plan",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute mailent fix --plan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Guided Remediation Only"));
    assert!(stdout.contains("SMTP STARTTLS Not Advertised"));
    assert!(stdout.contains("smtpd_tls_cert_file"));
    assert!(stdout.contains("smtpd_tls_key_file"));
}

#[test]
fn test_cli_fix_plan_starttls_missing_supported_when_certs_exist() {
    let dir = tempdir().unwrap();
    let cert_path = dir.path().join("fullchain.pem");
    let key_path = dir.path().join("privkey.pem");
    fs::write(&cert_path, "DUMMY CERTIFICATE").unwrap();
    fs::write(&key_path, "DUMMY PRIVATE KEY").unwrap();

    let config_path = dir.path().join("main.cf");
    let initial_content = format!(
        "myhostname = mail.example.com\nsmtpd_tls_cert_file = {}\nsmtpd_tls_key_file = {}\nsmtpd_tls_security_level = none\n",
        cert_path.display(),
        key_path.display()
    );
    fs::write(&config_path, initial_content).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "fix",
            "STARTTLS_MISSING",
            "--plan",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute mailent fix --plan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Mailent Remediation Plan"));
    assert!(stdout.contains("smtpd_tls_security_level"));
    assert!(stdout.contains("may"));
}

#[test]
fn test_cli_fix_plan_dovecot_tls_legacy() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("dovecot.conf");
    let initial_content = "ssl = yes\nssl_min_protocol = TLSv1\n";
    fs::write(&config_path, initial_content).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "fix",
            "TLS_LEGACY_VERSION",
            "--plan",
            "--service",
            "dovecot",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute mailent fix --plan");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Mailent Remediation Plan"));
    assert!(stdout.contains("Dovecot"));
    assert!(stdout.contains("ssl_min_protocol"));
    assert!(stdout.contains("TLSv1.2"));
    assert!(stdout.contains("doveconf -n"));
    assert!(stdout.contains("doveadm reload"));
}

#[test]
fn test_cli_fix_apply_postfix_and_verify_backup() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("main.cf");
    let initial_content = "myhostname = mail.example.com\nsmtpd_tls_protocols = !SSLv2, !SSLv3\nsmtpd_tls_mandatory_protocols = !SSLv2, !SSLv3\n";
    fs::write(&config_path, initial_content).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "fix",
            "TLS_LEGACY_VERSION",
            "--config",
            config_path.to_str().unwrap(),
            "--target",
            "127.0.0.1:65534", // closed port for offline test
            "--yes",
        ])
        .output()
        .expect("Failed to execute mailent fix");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[1/5]"));
    assert!(stdout.contains("Backing up configuration"));
    assert!(stdout.contains("[2/5]"));
    assert!(stdout.contains("Applying structured changes"));
    assert!(stdout.contains("[3/5]"));
    assert!(stdout.contains("Validating configuration syntax"));
    assert!(stdout.contains("[4/5]"));
    assert!(stdout.contains("Reloading service"));
    assert!(stdout.contains("[5/5]"));
    assert!(stdout.contains("Running active verification probe"));

    // Check modified configuration content
    let modified = fs::read_to_string(&config_path).unwrap();
    assert!(modified.contains("smtpd_tls_protocols = >=TLSv1.2, !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"));
    assert!(modified.contains("smtpd_tls_mandatory_protocols = >=TLSv1.2, !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"));

    // Verify backup was created and contains the original content
    let entries: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    let backup_entry = entries
        .iter()
        .find(|e| e.file_name().to_string_lossy().contains(".mailent-backup-"));
    assert!(backup_entry.is_some(), "Backup file should exist");
    let backup_content = fs::read_to_string(backup_entry.unwrap().path()).unwrap();
    assert_eq!(backup_content, initial_content);

    // Idempotency: run again and ensure it still passes cleanly
    let output2 = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "fix",
            "TLS_LEGACY_VERSION",
            "--config",
            config_path.to_str().unwrap(),
            "--target",
            "127.0.0.1:65534",
            "--yes",
        ])
        .output()
        .expect("Failed to execute mailent fix 2nd time");
    assert!(output2.status.success());
}

#[test]
fn test_cli_fix_manual_rollback() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("main.cf");
    let backup_path = dir.path().join("main.cf.mailent-backup-20260925-120000");

    let original_content = "myhostname = mail.example.com\noriginal_setting = true\n";
    let mutated_content = "myhostname = mail.example.com\nmutated_setting = true\n";

    fs::write(&backup_path, original_content).unwrap();
    fs::write(&config_path, mutated_content).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "fix",
            "TLS_LEGACY_VERSION",
            "--rollback",
            backup_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute mailent fix --rollback");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Mailent Manual Rollback"));
    assert!(stdout.contains("Successfully restored configuration"));

    // Verify file content was restored
    let restored_content = fs::read_to_string(&config_path).unwrap();
    assert_eq!(restored_content, original_content);
}

#[test]
fn test_cli_fix_rollback_on_validation_failure() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join("main.cf");
    // Config with a malformed line that triggers syntax validation failure
    let initial_content = "myhostname = mail.example.com\nmalformed_directive_without_equals\nsmtpd_tls_protocols = !SSLv2\n";
    fs::write(&config_path, initial_content).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_mailent"))
        .args([
            "fix",
            "TLS_LEGACY_VERSION",
            "--config",
            config_path.to_str().unwrap(),
            "--target",
            "127.0.0.1:65534",
            "--yes",
        ])
        .output()
        .expect("Failed to execute mailent fix");

    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("Validation failed") || stderr.contains("validation check failed"),
        "Output should indicate validation failure: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stdout.contains("Reverted configuration to initial state"),
        "Stdout should confirm automatic rollback: {stdout}"
    );

    // Verify file content was reverted to initial content
    let content_after = fs::read_to_string(&config_path).unwrap();
    assert_eq!(content_after, initial_content);
}

