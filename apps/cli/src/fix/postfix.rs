use std::path::{Path, PathBuf};
use std::process::Command;
use mailent_domain::{EmailProtocol, Finding, FindingSeverity};

use super::adapter::{AppliedDiff, ConfigChange, FixSupport, RemediationPlan, ServiceAdapter, ServiceKind};
use super::backup::{atomic_write, create_backup, restore_backup};

pub struct PostfixAdapter;

impl PostfixAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Parses main.cf and updates or appends parameters, cleanly handling continuation lines.
    pub fn update_params(
        content: &str,
        params: &[(&str, &str, &str)], // (key, value, reason)
    ) -> (String, Vec<ConfigChange>, Vec<String>) {
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut changes = Vec::new();
        let mut modified_keys = Vec::new();

        for &(key, new_value, reason) in params {
            let key_lower = key.to_ascii_lowercase();
            let mut found_index = None;
            let mut old_value = None;

            let mut i = 0;
            while i < lines.len() {
                let trimmed = lines[i].trim_start();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    i += 1;
                    continue;
                }

                if let Some((k, v)) = lines[i].split_once('=') {
                    if k.trim().to_ascii_lowercase() == key_lower {
                        found_index = Some(i);
                        let mut full_old_val = v.trim().to_string();

                        // Check and remove continuation lines
                        let next = i + 1;
                        while next < lines.len() {
                            let next_line = &lines[next];
                            if next_line.starts_with(' ') || next_line.starts_with('\t') {
                                full_old_val.push(' ');
                                full_old_val.push_str(next_line.trim());
                                lines.remove(next);
                            } else {
                                break;
                            }
                        }

                        old_value = Some(full_old_val);
                        break;
                    }
                }
                i += 1;
            }

            if let Some(idx) = found_index {
                let current_old = old_value.clone().unwrap_or_default();
                if current_old != new_value {
                    lines[idx] = format!("{key} = {new_value}");
                    changes.push(ConfigChange {
                        file_path: PathBuf::new(),
                        parameter: key.to_string(),
                        old_value,
                        new_value: new_value.to_string(),
                        description: reason.to_string(),
                    });
                    modified_keys.push(key.to_string());
                }
            } else {
                // Parameter does not exist, append with managed comment
                if !lines.is_empty() && !lines.last().map_or(true, |l| l.is_empty()) {
                    lines.push(String::new());
                }
                lines.push(format!("# Managed by Mailent: {reason}"));
                lines.push(format!("{key} = {new_value}"));
                changes.push(ConfigChange {
                    file_path: PathBuf::new(),
                    parameter: key.to_string(),
                    old_value: None,
                    new_value: new_value.to_string(),
                    description: reason.to_string(),
                });
                modified_keys.push(key.to_string());
            }
        }

        let mut output = lines.join("\n");
        if !output.ends_with('\n') {
            output.push('\n');
        }

        (output, changes, modified_keys)
    }

    /// Checks if certificate files referenced in main.cf or standard locations exist
    pub fn cert_files_exist(content: &str) -> bool {
        let mut cert_file = None;
        let mut key_file = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim().to_ascii_lowercase();
                let val = v.trim().trim_matches(['"', '\'']);
                if key == "smtpd_tls_cert_file" {
                    cert_file = Some(val.to_string());
                } else if key == "smtpd_tls_key_file" {
                    key_file = Some(val.to_string());
                }
            }
        }

        match (cert_file, key_file) {
            (Some(c), Some(k)) => Path::new(&c).exists() && Path::new(&k).exists(),
            _ => false,
        }
    }

    pub fn sync_to_container_if_running(config_path: &Path) {
        let path_str = config_path.to_string_lossy();
        if path_str.contains(".tmp") || path_str.contains("temp") || path_str.contains("/tmp/tmp") {
            return;
        }
        for engine in &["podman", "docker"] {
            if let Ok(output) = Command::new(engine).args(&["ps", "--format", "{{.Names}}"]).output() {
                let names = String::from_utf8_lossy(&output.stdout);
                for target_container in &["mail-server", "postfix", "mail"] {
                    if names.lines().any(|l| l.trim() == *target_container) {
                        let _ = Command::new(engine)
                            .args(&[
                                "cp",
                                &config_path.to_string_lossy(),
                                &format!("{target_container}:/etc/postfix/main.cf"),
                            ])
                            .output();
                    }
                }
            }
        }
    }
}

impl Default for PostfixAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceAdapter for PostfixAdapter {
    fn name(&self) -> &'static str {
        "Postfix"
    }

    fn service_kind(&self) -> ServiceKind {
        ServiceKind::Postfix
    }

    fn default_config_path(&self) -> &'static str {
        "/etc/postfix/main.cf"
    }

    fn detect(&self, config_override: Option<&Path>) -> Result<Option<PathBuf>, String> {
        if let Some(path) = config_override {
            if path.exists() {
                return Ok(Some(path.to_path_buf()));
            }
            return Ok(None);
        }

        let default_path = Path::new(self.default_config_path());
        if default_path.exists() {
            return Ok(Some(default_path.to_path_buf()));
        }

        // Check if `postconf` or `postfix` is installed
        let output = Command::new("postconf").arg("-d").arg("config_directory").output();
        if let Ok(out) = output {
            if out.status.success() {
                let dir_str = String::from_utf8_lossy(&out.stdout);
                if let Some(dir) = dir_str.split('=').nth(1) {
                    let candidate = Path::new(dir.trim()).join("main.cf");
                    if candidate.exists() {
                        return Ok(Some(candidate));
                    }
                }
            }
        }

        Ok(None)
    }

    fn plan(
        &self,
        rule_id: &str,
        finding: Option<&Finding>,
        config_path: &Path,
        target_override: Option<&str>,
    ) -> Result<FixSupport, String> {
        let content = std::fs::read_to_string(config_path)
            .map_err(|e| format!("Failed to read {}: {e}", config_path.display()))?;

        let backup_path = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!(
                "{}.mailent-backup-preview",
                config_path.file_name().and_then(|n| n.to_str()).unwrap_or("main.cf")
            ));

        let target_endpoint = target_override.unwrap_or("127.0.0.1:25").to_string();

        match rule_id {
            "TLS_LEGACY_VERSION" => {
                let modern_protocols = ">=TLSv1.2, !SSLv2, !SSLv3, !TLSv1, !TLSv1.1";
                let params = [
                    (
                        "smtpd_tls_protocols",
                        modern_protocols,
                        "Disable deprecated TLS 1.0 and 1.1 handshakes (RFC 8996)",
                    ),
                    (
                        "smtpd_tls_mandatory_protocols",
                        modern_protocols,
                        "Disable deprecated TLS 1.0 and 1.1 for mandatory TLS connections",
                    ),
                ];

                let (_, mut changes, _) = Self::update_params(&content, &params);
                for c in &mut changes {
                    c.file_path = config_path.to_path_buf();
                }

                Ok(FixSupport::Supported(RemediationPlan {
                    rule_id: "TLS_LEGACY_VERSION".to_string(),
                    finding_title: finding
                        .map(|f| f.title.clone())
                        .unwrap_or_else(|| "Deprecated TLS Version Negotiated".to_string()),
                    severity: finding.map(|f| f.severity).unwrap_or(FindingSeverity::Critical),
                    service_kind: ServiceKind::Postfix,
                    config_path: config_path.to_path_buf(),
                    changes,
                    backup_path,
                    validation_cmd: "postfix check".to_string(),
                    reload_cmd: "postfix reload".to_string(),
                    target_endpoint,
                    protocol: EmailProtocol::Smtp,
                    verification_steps: vec![
                        "Verify modern TLS handshake negotiation (TLS 1.2 or 1.3)".to_string(),
                        "Challenge TLS 1.0 handshake and verify explicit server protocol refusal".to_string(),
                        "Challenge TLS 1.1 handshake and verify explicit server protocol refusal".to_string(),
                    ],
                }))
            }

            "STARTTLS_MISSING" => {
                if !Self::cert_files_exist(&content) {
                    return Ok(FixSupport::GuidedOnly {
                        rule_id: "STARTTLS_MISSING".to_string(),
                        title: "SMTP STARTTLS Not Advertised".to_string(),
                        reason: "Postfix cannot enable STARTTLS because no readable TLS certificate (`smtpd_tls_cert_file`) and private key (`smtpd_tls_key_file`) were detected in configuration.".to_string(),
                        instructions: vec![
                            "1. Obtain a TLS certificate for your mail hostname (e.g., using `certbot certonly --standalone -d mail.example.com`).".to_string(),
                            "2. Configure `smtpd_tls_cert_file = /etc/letsencrypt/live/mail.example.com/fullchain.pem` in /etc/postfix/main.cf.".to_string(),
                            "3. Configure `smtpd_tls_key_file = /etc/letsencrypt/live/mail.example.com/privkey.pem` in /etc/postfix/main.cf.".to_string(),
                            "4. Once certificate files exist on disk, run `sudo mailent fix STARTTLS_MISSING` to enable opportunistic TLS.".to_string(),
                        ],
                    });
                }

                let params = [(
                    "smtpd_tls_security_level",
                    "may",
                    "Enable opportunistic STARTTLS for inbound mail connections (RFC 3207)",
                )];

                let (_, mut changes, _) = Self::update_params(&content, &params);
                for c in &mut changes {
                    c.file_path = config_path.to_path_buf();
                }

                Ok(FixSupport::Supported(RemediationPlan {
                    rule_id: "STARTTLS_MISSING".to_string(),
                    finding_title: finding
                        .map(|f| f.title.clone())
                        .unwrap_or_else(|| "SMTP STARTTLS Not Advertised".to_string()),
                    severity: finding.map(|f| f.severity).unwrap_or(FindingSeverity::High),
                    service_kind: ServiceKind::Postfix,
                    config_path: config_path.to_path_buf(),
                    changes,
                    backup_path,
                    validation_cmd: "postfix check".to_string(),
                    reload_cmd: "postfix reload".to_string(),
                    target_endpoint,
                    protocol: EmailProtocol::Smtp,
                    verification_steps: vec![
                        "Connect to SMTP endpoint and perform EHLO greeting".to_string(),
                        "Verify STARTTLS capability is advertised in 250 response".to_string(),
                        "Issue STARTTLS command, verify 220 acceptance, and establish TLS handshake".to_string(),
                    ],
                }))
            }

            "CERTIFICATE_EXPIRED" | "CERTIFICATE_INVALID" | "CERTIFICATE_SELF_SIGNED" => {
                Ok(FixSupport::GuidedOnly {
                    rule_id: rule_id.to_string(),
                    title: finding
                        .map(|f| f.title.clone())
                        .unwrap_or_else(|| "Certificate Validity Issue".to_string()),
                    reason: "Automated certificate issuance requires authoritative domain control and an external CA (e.g. Let's Encrypt ACME, step-ca, or enterprise PKI). Mailent does not possess your private DNS/ACME credentials.".to_string(),
                    instructions: vec![
                        "1. Request a renewed leaf certificate from your Certificate Authority covering your mail hostname.".to_string(),
                        "2. Deploy the renewed certificate and private key to the paths configured in `smtpd_tls_cert_file` and `smtpd_tls_key_file`.".to_string(),
                        "3. Reload Postfix using `postfix reload`.".to_string(),
                        "4. Run `mailent scan <domain>` to verify the new certificate validity and chain trust.".to_string(),
                    ],
                })
            }

            "NO_FORWARD_SECRECY" => {
                Ok(FixSupport::GuidedOnly {
                    rule_id: "NO_FORWARD_SECRECY".to_string(),
                    title: "Forward Secrecy Unavailable (Static RSA)".to_string(),
                    reason: "Proving static RSA refusal requires exhaustive cipher enumeration which is not conclusive from active probe handshakes.".to_string(),
                    instructions: vec![
                        "1. Configure ephemeral ECDH curves in /etc/postfix/main.cf: `smtpd_tls_eecdh_grade = auto`.".to_string(),
                        "2. Exclude static RSA cipher suites by setting: `smtpd_tls_exclude_ciphers = aNULL, eNULL, EXPORT, DES, RC4, MD5, PSK, aECDH, kRSA`.".to_string(),
                        "3. Run `postfix reload` and verify with `mailent scan` that forward secrecy is supported.".to_string(),
                    ],
                })
            }

            other => Ok(FixSupport::GuidedOnly {
                rule_id: other.to_string(),
                title: finding.map(|f| f.title.clone()).unwrap_or_else(|| other.to_string()),
                reason: format!("Finding {other} requires administrative infrastructure or external policy changes and cannot be safely automated locally."),
                instructions: vec![
                    "Consult Mailent documentation or run `mailent analyze --format json` for detailed guidance.".to_string(),
                ],
            }),
        }
    }

    fn apply(&self, plan: &RemediationPlan) -> Result<AppliedDiff, String> {
        let backup_path = create_backup(&plan.config_path)?;

        let content = std::fs::read_to_string(&plan.config_path)
            .map_err(|e| format!("Failed to read {}: {e}", plan.config_path.display()))?;

        let params: Vec<(&str, &str, &str)> = plan
            .changes
            .iter()
            .map(|c| (c.parameter.as_str(), c.new_value.as_str(), c.description.as_str()))
            .collect();

        let (new_content, _, _) = Self::update_params(&content, &params);

        if let Err(e) = atomic_write(&plan.config_path, &new_content) {
            let _ = restore_backup(&backup_path, &plan.config_path);
            return Err(e);
        }

        Self::sync_to_container_if_running(&plan.config_path);

        Ok(AppliedDiff {
            service_kind: ServiceKind::Postfix,
            config_path: plan.config_path.clone(),
            backup_path,
            changes: plan.changes.clone(),
        })
    }

    fn validate_config(&self, config_path: &Path) -> Result<(), String> {
        let mut cmd = Command::new("postfix");
        if let Some(parent) = config_path.parent() {
            if parent != Path::new("/etc/postfix") {
                cmd.arg("-c").arg(parent);
            }
        }
        cmd.arg("check");

        match cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(format!("`postfix check` failed: {stderr}"))
                }
            }
            Err(e) => {
                // If postfix binary is not in PATH (e.g. running in testing without postfix installed),
                // fall back to reading main.cf syntax check.
                let content = std::fs::read_to_string(config_path)
                    .map_err(|err| format!("Cannot read config for validation: {err}"))?;
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if !trimmed.contains('=') && !line.starts_with(' ') && !line.starts_with('\t') {
                        return Err(format!(
                            "Invalid configuration line {}: missing '=': {trimmed}",
                            idx + 1
                        ));
                    }
                }
                tracing::warn!("`postfix` binary not found in PATH ({e}); basic line syntax verified.");
                Ok(())
            }
        }
    }

    fn reload_service(&self) -> Result<(), String> {
        // 1. Try host postfix command first
        if let Ok(output) = Command::new("postfix").arg("reload").output() {
            if output.status.success() {
                return Ok(());
            }
        }

        // 2. If host postfix is not available or failed, check for podman/docker container
        for engine in &["podman", "docker"] {
            if let Ok(output) = Command::new(engine).args(&["ps", "--format", "{{.Names}}"]).output() {
                let names = String::from_utf8_lossy(&output.stdout);
                for target_container in &["mail-server", "postfix", "mail"] {
                    if names.lines().any(|l| l.trim() == *target_container) {
                        let rel = Command::new(engine)
                            .args(&["exec", target_container, "postfix", "reload"])
                            .output();
                        if let Ok(rel_out) = rel {
                            if rel_out.status.success() {
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }

        Err("`postfix reload` failed (neither host postfix nor container reloaded successfully)".to_string())
    }

    fn rollback(&self, backup_path: &Path, config_path: &Path) -> Result<(), String> {
        restore_backup(backup_path, config_path)?;
        Self::sync_to_container_if_running(config_path);
        let _ = self.reload_service();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_params_replaces_existing() {
        let sample = "myhostname = mail.example.com\nsmtpd_tls_protocols = >=TLSv1\nsmtpd_tls_security_level = may\n";
        let params = [("smtpd_tls_protocols", ">=TLSv1.2, !SSLv2, !SSLv3, !TLSv1, !TLSv1.1", "Disable legacy TLS")];
        let (updated, changes, keys) = PostfixAdapter::update_params(sample, &params);

        assert_eq!(changes.len(), 1);
        assert_eq!(keys, vec!["smtpd_tls_protocols"]);
        assert!(updated.contains("smtpd_tls_protocols = >=TLSv1.2, !SSLv2, !SSLv3, !TLSv1, !TLSv1.1"));
        assert!(!updated.contains(">=TLSv1\n"));
        assert!(updated.contains("myhostname = mail.example.com"));
    }

    #[test]
    fn test_update_params_handles_continuation_lines() {
        let sample = "myhostname = mail.example.com\nsmtpd_tls_protocols =\n    !SSLv2,\n    !SSLv3\nsmtpd_tls_security_level = may\n";
        let params = [("smtpd_tls_protocols", ">=TLSv1.2", "Set TLS 1.2 minimum")];
        let (updated, changes, _) = PostfixAdapter::update_params(sample, &params);

        assert_eq!(changes.len(), 1);
        assert!(updated.contains("smtpd_tls_protocols = >=TLSv1.2\nsmtpd_tls_security_level = may"));
        assert!(!updated.contains("!SSLv2"));
    }

    #[test]
    fn test_update_params_appends_missing() {
        let sample = "myhostname = mail.example.com\n";
        let params = [("smtpd_tls_protocols", ">=TLSv1.2", "Disable legacy TLS")];
        let (updated, changes, _) = PostfixAdapter::update_params(sample, &params);

        assert_eq!(changes.len(), 1);
        assert!(updated.contains("# Managed by Mailent: Disable legacy TLS\nsmtpd_tls_protocols = >=TLSv1.2"));
    }

    #[test]
    fn test_update_params_idempotent() {
        let sample = "myhostname = mail.example.com\nsmtpd_tls_protocols = >=TLSv1\n";
        let params = [("smtpd_tls_protocols", ">=TLSv1.2", "Disable legacy TLS")];
        let (first, changes1, _) = PostfixAdapter::update_params(sample, &params);
        assert_eq!(changes1.len(), 1);

        let (second, changes2, _) = PostfixAdapter::update_params(&first, &params);
        assert_eq!(changes2.len(), 0);
        assert_eq!(first, second);
    }
}
