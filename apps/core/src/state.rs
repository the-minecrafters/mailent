use mailent_baseline::{BaselineAnalyzer, DefaultBaselineAnalyzer};
use mailent_decision::{DecisionProvider, DisabledProvider, JevConfig, JevProvider};
use mailent_integrations::{
    DomainIntelligenceResolver, LiveDomainIntelligenceResolver, MockDomainIntelligenceResolver,
};
use mailent_policy::PolicyPack;
use mailent_storage::{
    StorageError,
    clickhouse::ClickHouseStorage,
    in_memory::InMemoryStorage,
    postgres::PostgresStorage,
    repository::{
        ArchivedReportRepository, AssessmentRepository, AssetRepository, BaselineRepository,
        CertificateRepository, DecisionRepository, FindingRepository, IntegrationRepository,
        IntelligenceRepository, InvestigationRepository, ObservationRepository, PostureRepository,
        ProbeRepository, RemediationRepository, SensorRepository, SessionRepository,
        TrainingRecordRepository,
    },
};
use std::sync::Arc;

use crate::config::CoreConfig;

#[derive(Clone)]
pub struct AppState {
    pub probe_config: Arc<mailent_probe::ProbeConfiguration>,
    pub probe_slots: Arc<tokio::sync::Semaphore>,
    pub policy_pack: Arc<PolicyPack>,
    pub storage_mode: String,
    pub decision_provider_name: String,
    pub assets: Arc<dyn AssetRepository>,
    pub certificates: Arc<dyn CertificateRepository>,
    pub sensors: Arc<dyn SensorRepository>,
    pub findings: Arc<dyn FindingRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub observations: Arc<dyn ObservationRepository>,
    pub intelligence: Arc<dyn IntelligenceRepository>,
    pub baselines: Arc<dyn BaselineRepository>,
    pub investigations: Arc<dyn InvestigationRepository>,
    pub decisions: Arc<dyn DecisionRepository>,
    pub probes: Arc<dyn ProbeRepository>,
    pub training: Arc<dyn TrainingRecordRepository>,
    pub remediations: Arc<dyn RemediationRepository>,
    pub postures: Arc<dyn PostureRepository>,
    pub integrations: Arc<dyn IntegrationRepository>,
    pub archived_reports: Arc<dyn ArchivedReportRepository>,
    pub assessments: Arc<dyn AssessmentRepository>,
    pub intelligence_resolver: Arc<dyn DomainIntelligenceResolver>,
    pub baseline_analyzer: Arc<dyn BaselineAnalyzer>,
    pub decision_provider: Arc<dyn DecisionProvider>,
}

impl AppState {
    pub fn new() -> Self {
        let mem = Arc::new(InMemoryStorage::new());
        let probe_config = mailent_probe::ProbeConfiguration::from_env();
        Self {
            storage_mode: "in_memory".into(),
            decision_provider_name: "disabled".into(),
            probe_slots: Arc::new(tokio::sync::Semaphore::new(probe_config.max_concurrency)),
            probe_config: Arc::new(probe_config),
            policy_pack: Arc::new(PolicyPack::modern()),
            assets: mem.clone(),
            certificates: mem.clone(),
            sensors: mem.clone(),
            findings: mem.clone(),
            sessions: mem.clone(),
            observations: mem.clone(),
            intelligence: mem.clone(),
            baselines: mem.clone(),
            investigations: mem.clone(),
            decisions: mem.clone(),
            probes: mem.clone(),
            training: mem.clone(),
            remediations: mem.clone(),
            postures: mem.clone(),
            integrations: mem.clone(),
            archived_reports: mem.clone(),
            assessments: mem.clone(),
            intelligence_resolver: Arc::new(MockDomainIntelligenceResolver::new()),
            baseline_analyzer: Arc::new(DefaultBaselineAnalyzer::new()),
            decision_provider: Arc::new(DisabledProvider),
        }
    }

    #[allow(clippy::type_complexity)]
    pub async fn from_config(config: &CoreConfig) -> Result<Self, StorageError> {
        let mem = Arc::new(InMemoryStorage::new());
        let pg_storage = if let Some(ref url) = config.database_url {
            Some(Arc::new(PostgresStorage::connect(url).await?))
        } else {
            None
        };

        let (
            assets,
            certificates,
            sensors,
            findings,
            intelligence,
            baselines,
            investigations,
            decisions,
            probes,
            training,
            remediations,
            postures,
            integrations,
            archived_reports,
            assessments,
        ): (
            Arc<dyn AssetRepository>,
            Arc<dyn CertificateRepository>,
            Arc<dyn SensorRepository>,
            Arc<dyn FindingRepository>,
            Arc<dyn IntelligenceRepository>,
            Arc<dyn BaselineRepository>,
            Arc<dyn InvestigationRepository>,
            Arc<dyn DecisionRepository>,
            Arc<dyn ProbeRepository>,
            Arc<dyn TrainingRecordRepository>,
            Arc<dyn RemediationRepository>,
            Arc<dyn PostureRepository>,
            Arc<dyn IntegrationRepository>,
            Arc<dyn ArchivedReportRepository>,
            Arc<dyn AssessmentRepository>,
        ) = if let Some(ref pg) = pg_storage {
            tracing::info!("Connecting to PostgreSQL control plane storage (with in-memory guest support)");
            let dual = Arc::new(crate::dual_storage::DualStorage::new(pg.clone(), mem.clone()));
            (
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual.clone(),
                dual,
            )
        } else {
            tracing::warn!(
                "No MAILENT_DATABASE_URL provided; using in-memory control plane storage"
            );
            (
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
                mem.clone(),
            )
        };

        let (sessions, observations): (Arc<dyn SessionRepository>, Arc<dyn ObservationRepository>) =
            if let Some(ref ch_url) = config.clickhouse_url {
                tracing::info!(clickhouse_url = %ch_url, database = %config.clickhouse_database, "Connecting to ClickHouse analytical storage");
                let ch = Arc::new(
                    ClickHouseStorage::connect(ch_url, &config.clickhouse_database).await?,
                );
                (ch.clone(), ch)
            } else if let Some(ref pg) = pg_storage {
                let dual = Arc::new(crate::dual_storage::DualStorage::new(pg.clone(), mem.clone()));
                (dual.clone(), dual)
            } else {
                tracing::warn!(
                    "No MAILENT_CLICKHOUSE_URL provided; using in-memory analytical storage"
                );
                (mem.clone(), mem)
            };

        let intelligence_resolver: Arc<dyn DomainIntelligenceResolver> = if let Some(ref doh) =
            config.doh_endpoint
        {
            match LiveDomainIntelligenceResolver::with_doh(doh) {
                Ok(r) => Arc::new(r),
                Err(e) => {
                    tracing::warn!(
                        "Failed to init LiveDomainIntelligenceResolver with DoH: {e}, falling back to mock"
                    );
                    Arc::new(MockDomainIntelligenceResolver::new())
                }
            }
        } else {
            match LiveDomainIntelligenceResolver::new() {
                Ok(r) => Arc::new(r),
                Err(e) => {
                    tracing::warn!(
                        "Failed to init LiveDomainIntelligenceResolver: {e}, falling back to mock"
                    );
                    Arc::new(MockDomainIntelligenceResolver::new())
                }
            }
        };

        let decision_provider: Arc<dyn DecisionProvider> = if config.jev_enabled {
            let mut jev_cfg = JevConfig::default();
            if let Some(ref base_url) = config.jev_base_url {
                jev_cfg.base_url = base_url.clone();
            }
            if let Some(ref api_key) = config.jev_api_key {
                jev_cfg.api_key = api_key.clone();
            }
            if let Some(ref model) = config.jev_model {
                jev_cfg.model = model.clone();
            }
            Arc::new(JevProvider::new(jev_cfg))
        } else {
            Arc::new(DisabledProvider)
        };

        let probe_config = mailent_probe::ProbeConfiguration::from_env();
        Ok(Self {
            decision_provider_name: if config.jev_enabled
                && config.jev_api_key.as_ref().is_some_and(|k| !k.is_empty())
            {
                "jev"
            } else {
                "disabled"
            }
            .into(),
            storage_mode: if config.database_url.is_some() {
                if config.clickhouse_url.is_some() {
                    "postgres_clickhouse"
                } else {
                    "postgres"
                }
            } else {
                "in_memory"
            }
            .into(),
            probe_slots: Arc::new(tokio::sync::Semaphore::new(probe_config.max_concurrency)),
            probe_config: Arc::new(probe_config),
            policy_pack: Arc::new(PolicyPack::modern()),
            assets,
            certificates,
            sensors,
            findings,
            sessions,
            observations,
            intelligence,
            baselines,
            investigations,
            decisions,
            probes,
            training,
            remediations,
            postures,
            integrations,
            archived_reports,
            assessments,
            intelligence_resolver,
            baseline_analyzer: Arc::new(DefaultBaselineAnalyzer::new()),
            decision_provider,
        })
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
