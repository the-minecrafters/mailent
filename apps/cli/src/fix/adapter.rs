use std::path::{Path, PathBuf};
use mailent_domain::{EmailProtocol, Finding, FindingSeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceKind {
    Postfix,
    Dovecot,
}

impl std::fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Postfix => write!(f, "Postfix"),
            Self::Dovecot => write!(f, "Dovecot"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigChange {
    pub file_path: PathBuf,
    pub parameter: String,
    pub old_value: Option<String>,
    pub new_value: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub rule_id: String,
    pub finding_title: String,
    pub severity: FindingSeverity,
    pub service_kind: ServiceKind,
    pub config_path: PathBuf,
    pub changes: Vec<ConfigChange>,
    pub backup_path: PathBuf,
    pub validation_cmd: String,
    pub reload_cmd: String,
    pub target_endpoint: String,
    pub protocol: EmailProtocol,
    pub verification_steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixSupport {
    Supported(RemediationPlan),
    GuidedOnly {
        rule_id: String,
        title: String,
        reason: String,
        instructions: Vec<String>,
    },
    #[allow(dead_code)]
    UnsupportedService {
        service: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedDiff {
    pub service_kind: ServiceKind,
    pub config_path: PathBuf,
    pub backup_path: PathBuf,
    pub changes: Vec<ConfigChange>,
}

pub trait ServiceAdapter: Send + Sync {
    fn name(&self) -> &'static str;
    #[allow(dead_code)]
    fn service_kind(&self) -> ServiceKind;
    fn default_config_path(&self) -> &'static str;
    fn detect(&self, config_override: Option<&Path>) -> Result<Option<PathBuf>, String>;
    fn plan(
        &self,
        rule_id: &str,
        finding: Option<&Finding>,
        config_path: &Path,
        target_override: Option<&str>,
    ) -> Result<FixSupport, String>;
    fn apply(&self, plan: &RemediationPlan) -> Result<AppliedDiff, String>;
    fn validate_config(&self, config_path: &Path) -> Result<(), String>;
    fn reload_service(&self) -> Result<(), String>;
    fn rollback(&self, backup_path: &Path, config_path: &Path) -> Result<(), String>;
}
