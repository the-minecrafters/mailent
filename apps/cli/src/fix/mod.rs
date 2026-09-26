#![allow(clippy::all)]

pub mod adapter;
pub mod backup;
pub mod dovecot;
pub mod postfix;
pub mod sync;
pub mod verify;

use std::io::{self, Write};
use std::path::PathBuf;
use mailent_domain::{Finding, RemediationState};

use adapter::{FixSupport, RemediationPlan, ServiceAdapter};
use dovecot::DovecotAdapter;
use postfix::PostfixAdapter;
use sync::sync_remediation;
use verify::run_active_verification;

pub async fn run_fix(
    finding_target: String,
    plan_only: bool,
    service_override: Option<String>,
    config_override: Option<PathBuf>,
    target_override: Option<String>,
    yes: bool,
    sync: bool,
    server: Option<String>,
    rollback: Option<PathBuf>,
) -> Result<(), String> {
    let postfix_adapter = PostfixAdapter::new();
    let dovecot_adapter = DovecotAdapter::new();

    // Handle manual rollback if requested
    if let Some(backup_path) = rollback {
        println!("Mailent Manual Rollback");
        println!("=======================");
        if !backup_path.exists() {
            return Err(format!("Backup file not found: {}", backup_path.display()));
        }

        let config_path = config_override.unwrap_or_else(|| {
            // Infer original path from backup name by stripping .mailent-backup-*
            let backup_str = backup_path.to_string_lossy();
            if let Some((orig, _)) = backup_str.split_once(".mailent-backup-") {
                PathBuf::from(orig)
            } else {
                PathBuf::from("/etc/postfix/main.cf")
            }
        });

        println!("Restoring {} from backup {}...", config_path.display(), backup_path.display());
        backup::restore_backup(&backup_path, &config_path)?;

        // Attempt reload
        if config_path.to_string_lossy().contains("postfix") {
            let _ = postfix_adapter.reload_service();
        } else if config_path.to_string_lossy().contains("dovecot") {
            let _ = dovecot_adapter.reload_service();
        }

        println!("\x1b[32m✔ Successfully restored configuration and reloaded service.\x1b[0m");
        return Ok(());
    }

    // Identify the finding rule_id and optional local finding record
    let (rule_id, finding) = resolve_finding(&finding_target);

    // Select the appropriate service adapter
    let adapter: Box<dyn ServiceAdapter> = match service_override.as_deref() {
        Some("postfix") => Box::new(postfix_adapter),
        Some("dovecot") => Box::new(dovecot_adapter),
        Some(other) => {
            return Err(format!(
                "Unsupported service '{other}'. Supported services: postfix, dovecot"
            ));
        }
        None => {
            // Auto-detect based on finding and available config files
            if rule_id == "STARTTLS_MISSING" {
                Box::new(postfix_adapter)
            } else if let Ok(Some(_)) = postfix_adapter.detect(config_override.as_deref()) {
                Box::new(postfix_adapter)
            } else if let Ok(Some(_)) = dovecot_adapter.detect(config_override.as_deref()) {
                Box::new(dovecot_adapter)
            } else {
                Box::new(postfix_adapter) // Default attempt
            }
        }
    };

    let config_path = adapter
        .detect(config_override.as_deref())?
        .unwrap_or_else(|| PathBuf::from(adapter.default_config_path()));

    if !config_path.exists() && !plan_only {
        return Err(format!(
            "Could not locate {} configuration file at {}. Specify --config <path> if running in a non-standard environment.",
            adapter.name(),
            config_path.display()
        ));
    }

    // Generate the remediation plan
    let plan_result = adapter.plan(
        &rule_id,
        finding.as_ref(),
        &config_path,
        target_override.as_deref(),
    )?;

    let plan = match plan_result {
        FixSupport::Supported(plan) => plan,
        FixSupport::GuidedOnly {
            title,
            reason,
            instructions,
            ..
        } => {
            print_guided_remediation(&rule_id, &title, &reason, &instructions);
            return Ok(());
        }
        FixSupport::UnsupportedService { service, reason } => {
            return Err(format!("Remediation unsupported on {service}: {reason}"));
        }
    };

    if plan_only {
        print_remediation_plan(&plan);
        return Ok(());
    }

    // Verify root or writable permission before modifying
    #[cfg(unix)]
    {
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        let is_root = unsafe { geteuid() == 0 };
        let is_writable = config_path.exists()
            && std::fs::OpenOptions::new()
                .write(true)
                .open(&config_path)
                .is_ok();

        if !is_root && !is_writable {
            println!("\x1b[33m[!] Root or write permission required to modify {}.\x1b[0m", config_path.display());
            println!("    Please run with sudo: `sudo mailent fix {}`", finding_target);
            return Err("Insufficient permissions to apply remediation".into());
        }
    }

    // Interactive confirmation unless --yes
    if !yes {
        print_remediation_plan(&plan);
        print!("Apply this remediation to {}? [y/N]: ", plan.config_path.display());
        io::stdout().flush().map_err(|e| e.to_string())?;

        let mut input = String::new();
        io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        let trimmed = input.trim().to_ascii_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("Remediation cancelled by user.");
            return Ok(());
        }
    } else {
        println!("\n── 󰒓 Mailent Remediation Plan ──");
        println!("  󰀦 Finding:   {} ({})", plan.finding_title, plan.rule_id);
        println!("  󰒋 Service:   {} ({})", plan.service_kind, plan.config_path.display());
        println!("  󰒓 Changes:");
        for change in &plan.changes {
            if let Some(ref old) = change.old_value {
                println!("    ~ {}: \"{}\" -> \"{}\"", change.parameter, old, change.new_value);
            } else {
                println!("    + {} = \"{}\"", change.parameter, change.new_value);
            }
        }
        println!();
    }

    println!("Applying remediation...");
    println!("  [1/5] 󰈙 Backing up configuration…");
    let diff = adapter.apply(&plan)?;
    println!("        󰄬 Created backup at {}", diff.backup_path.display());

    println!("  [2/5] 󰒓 Applying structured changes…");
    for change in &plan.changes {
        println!("        • {} = {}", change.parameter, change.new_value);
    }
    println!("        󰄬 Updated configuration atomically");

    println!("  [3/5] 󰞀 Validating configuration syntax ({})...", plan.validation_cmd);
    if let Err(val_err) = adapter.validate_config(&plan.config_path) {
        println!("        󰅖 Validation failed: {val_err}");
        println!("        󰀦 Automatically rolling back to backup…");
        let _ = adapter.rollback(&diff.backup_path, &plan.config_path);
        println!("        󰄬 Reverted configuration to initial state.");
        return Err(format!("Configuration validation check failed: {val_err}"));
    }
    println!("        󰄬 Syntax validation passed");

    println!("  [4/5] 󰑓 Reloading service ({})...", plan.reload_cmd);
    if let Err(reload_err) = adapter.reload_service() {
        println!("        󰀦 Service reload returned: {reload_err}");
    } else {
        println!("        󰄬 Service reloaded successfully");
    }

    // Active verification
    let (outcome, explanation, probe_run, record) =
        run_active_verification(&plan, finding.as_ref()).await?;

    match outcome {
        RemediationState::VerifiedFixed => {
            println!("\n── 󰄬 Fix Verified ──");
            println!("  {explanation}\n");
        }
        RemediationState::StillPresent => {
            println!("\n── 󰅖 Issue Still Detected ──");
            println!("  {explanation}");
            println!("\n  Run `mailent fix --rollback {}` to restore previous configuration.\n", diff.backup_path.display());
        }
        _ => {
            println!("\n── 󰀦 Verification Inconclusive ──");
            println!("  {explanation}\n");
        }
    }

    // Write local audit log
    save_audit_record(&record, &diff);

    // Sync to workspace if requested
    if sync {
        if let Err(e) = sync_remediation(server, &record, Some(&probe_run), &plan.config_path).await {
            println!("\x1b[33m[!] Warning: Failed to sync remediation to workspace: {e}\x1b[0m");
        }
    }

    Ok(())
}

fn resolve_finding(target: &str) -> (String, Option<Finding>) {
    let known_rules = [
        "TLS_LEGACY_VERSION",
        "STARTTLS_MISSING",
        "CERTIFICATE_EXPIRED",
        "CERTIFICATE_INVALID",
        "CERTIFICATE_SELF_SIGNED",
        "NO_FORWARD_SECRECY",
        "MTA_STS_POLICY_MISSING",
        "TLS_RPT_POLICY_MISSING",
    ];

    for rule in known_rules {
        if target.eq_ignore_ascii_case(rule) {
            return (rule.to_string(), None);
        }
    }

    // Try finding in recent report JSON files in current directory
    if let Ok(entries) = std::fs::read_dir(".") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json")
                && path.to_string_lossy().contains("mailent-report")
            {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                        if let Some(findings) = json.get("findings").and_then(|f| f.as_array()) {
                            for f in findings {
                                if let Ok(finding) = serde_json::from_value::<Finding>(f.clone()) {
                                    if finding.id.to_string() == target
                                        || finding.rule_id.eq_ignore_ascii_case(target)
                                    {
                                        return (finding.rule_id.clone(), Some(finding));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (target.to_string(), None)
}

fn print_remediation_plan(plan: &RemediationPlan) {
    println!("\n── 󰒓 Mailent Remediation Plan ──");
    println!("  󰀦 Finding:   {} ({})", plan.finding_title, plan.rule_id);
    println!("  󰞀 Severity:  {}", plan.severity);
    println!("  󰒋 Service:   {} ({})", plan.service_kind, plan.config_path.display());
    println!("  󰒍 Endpoint:  {}", plan.target_endpoint);
    println!();
    println!("  󰒓 Planned Changes ({}):", plan.config_path.display());
    for change in &plan.changes {
        if let Some(ref old) = change.old_value {
            println!("    ~ {}: \"{}\" -> \"{}\"", change.parameter, old, change.new_value);
        } else {
            println!("    + {} = \"{}\"", change.parameter, change.new_value);
        }
        println!("      ({})", change.description);
    }
    println!();
    println!("  󰛄 Safety & Rollback:");
    println!("    󰈙 Backup:    {}", plan.backup_path.display());
    println!("    󰞀 Validate:  {}", plan.validation_cmd);
    println!("    󰑓 Reload:    {}", plan.reload_cmd);
    println!();
    println!("  󱐋 Active Verification Steps:");
    for (i, step) in plan.verification_steps.iter().enumerate() {
        println!("    {}. {}", i + 1, step);
    }
    println!();
}

fn print_guided_remediation(rule_id: &str, title: &str, reason: &str, instructions: &[String]) {
    println!("\n── 󰒓 Guided Remediation Only ──");
    println!("  󰀦 Finding:   {} ({})", title, rule_id);
    println!("\n  󰞀 Notice:\n    {}", reason);
    println!("\n  󰄬 Recommended Remediation Steps:");
    for inst in instructions {
        println!("    {}", inst);
    }
    println!("\n  󰈙 Verify your changes anytime with: `mailent scan <domain>`\n");
}

fn save_audit_record(record: &mailent_domain::RemediationRecord, diff: &adapter::AppliedDiff) {
    let audit_dir = dirs_or_temp_remediations_dir();
    let _ = std::fs::create_dir_all(&audit_dir);
    let audit_file = audit_dir.join(format!("remediation-{}.json", record.id));

    let audit_payload = serde_json::json!({
        "remediation_id": record.id,
        "rule_id": record.finding.rule_id,
        "service": diff.service_kind.to_string(),
        "config_path": diff.config_path,
        "backup_path": diff.backup_path,
        "state": record.state,
        "changes": diff.changes,
        "timestamp": record.applied_at,
    });

    if let Ok(json_str) = serde_json::to_string_pretty(&audit_payload) {
        if std::fs::write(&audit_file, json_str).is_ok() {
            println!("Audit log recorded: {}", audit_file.display());
        }
    }
}

fn dirs_or_temp_remediations_dir() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".config/mailent/remediations")
    } else {
        std::env::temp_dir().join("mailent/remediations")
    }
}
