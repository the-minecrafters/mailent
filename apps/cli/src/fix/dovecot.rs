use std::path::{Path, PathBuf};
use std::process::Command;
use mailent_domain::{EmailProtocol, Finding, FindingSeverity};

use super::adapter::{AppliedDiff, ConfigChange, FixSupport, RemediationPlan, ServiceAdapter, ServiceKind};
use super::backup::{atomic_write, create_backup, restore_backup};

pub struct DovecotAdapter;

impl DovecotAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Parses dovecot.conf and updates or appends parameters.
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

            for (i, line) in lines.iter().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    continue;
                }

                if let Some((k, v)) = line.split_once('=') {
                    if k.trim().to_ascii_lowercase() == key_lower {
                        found_index = Some(i);
                        old_value = Some(v.trim().to_string());
                        break;
                    }
                }
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

    pub fn sync_to_container_if_running(config_path: &Path) {
        let path_str = config_path.to_string_lossy();
        if path_str.contains(".tmp") || path_str.contains("temp") || path_str.contains("/tmp/tmp") {
            return;
        }
        for engine in &["podman", "docker"] {
            if let Ok(output) = Command::new(engine).args(&["ps", "--format", "{{.Names}}"]).output() {
                let names = String::from_utf8_lossy(&output.stdout);
                for target_container in &["mail-server", "dovecot", "mail"] {
                    if names.lines().any(|l| l.trim() == *target_container) {
                        let _ = Command::new(engine)
                            .args(&[
                                "cp",
                                &config_path.to_string_lossy(),
                                &format!("{target_container}:/etc/dovecot/dovecot.conf"),
                            ])
                            .output();
                    }
                }
            }
        }
    }
}

impl Default for DovecotAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceAdapter for DovecotAdapter {
    fn name(&self) -> &'static str {
        "Dovecot"
    }

    fn service_kind(&self) -> ServiceKind {
        ServiceKind::Dovecot
    }

    fn default_config_path(&self) -> &'static str {
        "/etc/dovecot/dovecot.conf"
    }

    fn detect(&self, config_override: Option<&Path>) -> Result<Option<PathBuf>, String> {
        if let Some(path) = config_override {
            if path.exists() {
                return Ok(Some(path.to_path_buf()));
            }
            return Ok(None);
        }

        let default_conf = Path::new(self.default_config_path());
        if default_conf.exists() {
            return Ok(Some(default_conf.to_path_buf()));
        }

        let ssl_conf = Path::new("/etc/dovecot/conf.d/10-ssl.conf");
        if ssl_conf.exists() {
            return Ok(Some(ssl_conf.to_path_buf()));
        }

        // Try `doveconf` command to find config file
        let output = Command::new("doveconf").arg("-n").output();
        if let Ok(out) = output {
            if out.status.success() && default_conf.exists() {
                return Ok(Some(default_conf.to_path_buf()));
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
                config_path.file_name().and_then(|n| n.to_str()).unwrap_or("dovecot.conf")
            ));

        let target_endpoint = target_override.unwrap_or("127.0.0.1:143").to_string();

        match rule_id {
            "TLS_LEGACY_VERSION" => {
                let params = [(
                    "ssl_min_protocol",
                    "TLSv1.2",
                    "Disable legacy TLS 1.0 and 1.1 handshakes in Dovecot (RFC 8996)",
                )];

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
                    service_kind: ServiceKind::Dovecot,
                    config_path: config_path.to_path_buf(),
                    changes,
                    backup_path,
                    validation_cmd: "doveconf -n".to_string(),
                    reload_cmd: "doveadm reload".to_string(),
                    target_endpoint,
                    protocol: EmailProtocol::Imap,
                    verification_steps: vec![
                        "Verify modern TLS handshake on IMAP (port 143) / POP3 (port 110)".to_string(),
                        "Challenge TLS 1.0 handshake and verify explicit server protocol refusal".to_string(),
                        "Challenge TLS 1.1 handshake and verify explicit server protocol refusal".to_string(),
                    ],
                }))
            }

            "CERTIFICATE_EXPIRED" | "CERTIFICATE_INVALID" | "CERTIFICATE_SELF_SIGNED" => {
                Ok(FixSupport::GuidedOnly {
                    rule_id: rule_id.to_string(),
                    title: finding
                        .map(|f| f.title.clone())
                        .unwrap_or_else(|| "Certificate Validity Issue".to_string()),
                    reason: "Automated certificate issuance requires authoritative domain control and an external CA (e.g. Let's Encrypt ACME, step-ca, or enterprise PKI).".to_string(),
                    instructions: vec![
                        "1. Request a renewed leaf certificate from your Certificate Authority.".to_string(),
                        "2. Update `ssl_cert = </path/to/cert.pem` and `ssl_key = </path/to/privkey.pem` in Dovecot config.".to_string(),
                        "3. Reload Dovecot using `doveadm reload`.".to_string(),
                        "4. Run `mailent scan <domain>` to verify certificate validity.".to_string(),
                    ],
                })
            }

            other => Ok(FixSupport::GuidedOnly {
                rule_id: other.to_string(),
                title: finding.map(|f| f.title.clone()).unwrap_or_else(|| other.to_string()),
                reason: format!("Finding {other} requires administrative infrastructure changes and cannot be safely automated locally in Dovecot."),
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
            service_kind: ServiceKind::Dovecot,
            config_path: plan.config_path.clone(),
            backup_path,
            changes: plan.changes.clone(),
        })
    }

    fn validate_config(&self, config_path: &Path) -> Result<(), String> {
        let mut cmd = Command::new("doveconf");
        cmd.arg("-n");
        if let Some(parent) = config_path.parent() {
            if parent != Path::new("/etc/dovecot") {
                cmd.arg("-c").arg(config_path);
            }
        }

        match cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    Ok(())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    Err(format!("`doveconf -n` validation failed: {stderr}"))
                }
            }
            Err(e) => {
                // If doveconf is not installed, verify basic line syntax
                let content = std::fs::read_to_string(config_path)
                    .map_err(|err| format!("Cannot read config for validation: {err}"))?;
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.ends_with('{') || trimmed == "}" {
                        continue;
                    }
                    if !trimmed.contains('=') && !line.starts_with(' ') && !line.starts_with('\t') {
                        return Err(format!(
                            "Invalid Dovecot configuration line {}: missing '=': {trimmed}",
                            idx + 1
                        ));
                    }
                }
                tracing::warn!("`doveconf` binary not found in PATH ({e}); basic line syntax verified.");
                Ok(())
            }
        }
    }

    fn reload_service(&self) -> Result<(), String> {
        // 1. Try host doveadm
        if let Ok(output) = Command::new("doveadm").arg("reload").output() {
            if output.status.success() {
                return Ok(());
            }
        }

        // 2. Try container engines
        for engine in &["podman", "docker"] {
            if let Ok(output) = Command::new(engine).args(&["ps", "--format", "{{.Names}}"]).output() {
                let names = String::from_utf8_lossy(&output.stdout);
                for target_container in &["mail-server", "dovecot", "mail"] {
                    if names.lines().any(|l| l.trim() == *target_container) {
                        let rel = Command::new(engine)
                            .args(&["exec", target_container, "doveadm", "reload"])
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

        Err("`doveadm reload` failed (neither host dovecot nor container reloaded successfully)".to_string())
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
    fn test_dovecot_update_params() {
        let sample = "protocols = imap pop3\nssl_min_protocol = TLSv1\nssl = yes\n";
        let params = [("ssl_min_protocol", "TLSv1.2", "Require TLS 1.2")];
        let (updated, changes, keys) = DovecotAdapter::update_params(sample, &params);

        assert_eq!(changes.len(), 1);
        assert_eq!(keys, vec!["ssl_min_protocol"]);
        assert!(updated.contains("ssl_min_protocol = TLSv1.2"));
        assert!(!updated.contains("TLSv1\n"));
        assert!(updated.contains("protocols = imap pop3"));
    }

    #[test]
    fn test_dovecot_append_param() {
        let sample = "protocols = imap pop3\nssl = yes\n";
        let params = [("ssl_min_protocol", "TLSv1.2", "Require TLS 1.2")];
        let (updated, changes, _) = DovecotAdapter::update_params(sample, &params);

        assert_eq!(changes.len(), 1);
        assert!(updated.contains("# Managed by Mailent: Require TLS 1.2\nssl_min_protocol = TLSv1.2"));
    }
}
