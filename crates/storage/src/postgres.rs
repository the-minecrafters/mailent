use async_trait::async_trait;
use mailent_domain::{
    AgentJob, AgentJobType, AnomalySignal, AssessmentRecord, AssessmentSource, AssessmentSummary,
    Asset, AssetBaseline, AssetEndpoint, AssetIdentity, CaptureMetadata, CertificateRecord,
    CtCertificateRecord, CtIntelligenceEvent, CtIntelligenceEventKind, DecisionRecord,
    DecisionResult, Device, DeviceAuthorizationChallenge, DnssecState, DriftEvent, DriftKind,
    EmailProtocol, EvidenceRef, Finding, FindingCategory, FindingSeverity, InfrastructureMonitor,
    IntelligenceRefreshStatus, Investigation, InvestigationStatus, JobExecutionTarget, JobState,
    MonitorCadence, MonitorExecutionTarget, MtaStsMode, MtaStsPolicy, MxRecord, Organization,
    OrganizationMember, PerspectiveMismatch, PriorityLevel, ProbeOutcome, ProbeResult, ProbeRun,
    ProbeTrigger, RiskLevel, SensorHeartbeat, SensorRecord, SensorStatus, TlsRptAggregateReport,
    TlsRptPolicy, TlsVersion, TlsaRecord, TrainingRecord,
};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    error::StorageError,
    repository::{
        ArchivedReportRepository, AssessmentRepository, AssetRepository, BaselineRepository,
        CertificateRepository, DecisionRepository, DeviceRepository, FindingRepository,
        IntegrationRepository, IntelligenceRepository, InvestigationRepository, JobRepository,
        MonitorRepository, OrganizationRepository, PostureRepository, ProbeRepository,
        SensorRepository, TrainingRecordRepository,
    },
};

#[derive(Clone)]
pub struct PostgresStorage {
    pool: Arc<PgPool>,
}

impl PostgresStorage {
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let mut options: sqlx::postgres::PgConnectOptions = database_url
            .parse()
            .map_err(|e| StorageError::Backend(format!("Invalid database URL: {e}")))?;
        if let Ok(schema) = std::env::var("MAILENT_DATABASE_SCHEMA") {
            if !schema
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                || schema.is_empty()
            {
                return Err(StorageError::Backend("Invalid database schema".into()));
            }
            options = options.options([("search_path", schema)]);
        }
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|e| StorageError::Backend(format!("PostgreSQL connection failed: {e}")))?;

        let storage = Self {
            pool: Arc::new(pool),
        };
        if std::env::var("MAILENT_RUN_MIGRATIONS").as_deref() != Ok("false") {
            storage.migrate().await?;
        }
        Ok(storage)
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self {
            pool: Arc::new(pool),
        }
    }

    pub async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::migrate!("migrations/postgres")
            .run(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(format!("PostgreSQL migration failed: {e}")))?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl AssetRepository for PostgresStorage {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Asset>, StorageError> {
        let row = sqlx::query(
            "SELECT id, primary_name, addresses, hostnames, tls_versions, cipher_suites, certificate_fingerprints, active_findings_count, first_seen, last_seen, organization_id FROM assets WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find_by_id asset error: {e}")))?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let identities = self.load_identities_for_asset(id).await?;
        let endpoints = self.load_endpoints_for_asset(id).await?;

        let raw_tls: Vec<String> = row.get("tls_versions");
        let tls_versions = raw_tls.into_iter().map(parse_tls_version).collect();

        Ok(Some(Asset {
            id: row.get("id"),
            primary_name: row.get("primary_name"),
            addresses: row.get("addresses"),
            hostnames: row.get("hostnames"),
            identities,
            endpoints,
            tls_versions,
            cipher_suites: row.get("cipher_suites"),
            certificate_fingerprints: row.get("certificate_fingerprints"),
            active_findings_count: row.get::<i32, _>("active_findings_count") as usize,
            first_seen: row.get("first_seen"),
            last_seen: row.get("last_seen"),
            organization_id: row.try_get("organization_id").ok(),
        }))
    }

    async fn find_by_address_or_identity(
        &self,
        identity: &str,
    ) -> Result<Option<Asset>, StorageError> {
        let row = sqlx::query(
            "SELECT a.id FROM assets a LEFT JOIN asset_identities i ON a.id = i.asset_id WHERE $1 = ANY(a.addresses) OR $1 = ANY(a.hostnames) OR i.value = $1 LIMIT 1"
        )
        .bind(identity)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find_by_address_or_identity error: {e}")))?;

        if let Some(r) = row {
            let asset_id: Uuid = r.get("id");
            AssetRepository::find_by_id(self, asset_id).await
        } else {
            Ok(None)
        }
    }

    async fn upsert(&self, asset: Asset) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        let raw_tls: Vec<String> = asset.tls_versions.iter().map(|v| v.to_string()).collect();

        sqlx::query(
            r#"INSERT INTO assets (id, primary_name, addresses, hostnames, tls_versions, cipher_suites, certificate_fingerprints, active_findings_count, first_seen, last_seen)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (id) DO UPDATE SET
                   primary_name = COALESCE(EXCLUDED.primary_name, assets.primary_name),
                   addresses = EXCLUDED.addresses,
                   hostnames = EXCLUDED.hostnames,
                   tls_versions = EXCLUDED.tls_versions,
                   cipher_suites = EXCLUDED.cipher_suites,
                   certificate_fingerprints = EXCLUDED.certificate_fingerprints,
                   active_findings_count = EXCLUDED.active_findings_count,
                   last_seen = EXCLUDED.last_seen"#
        )
        .bind(asset.id)
        .bind(&asset.primary_name)
        .bind(&asset.addresses)
        .bind(&asset.hostnames)
        .bind(&raw_tls)
        .bind(&asset.cipher_suites)
        .bind(&asset.certificate_fingerprints)
        .bind(asset.active_findings_count as i32)
        .bind(asset.first_seen)
        .bind(asset.last_seen)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::Backend(format!("upsert asset error: {e}")))?;

        for ident in &asset.identities {
            sqlx::query(
                r#"INSERT INTO asset_identities (id, asset_id, kind, value, first_seen, last_seen)
                   VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (asset_id, kind, value) DO UPDATE SET
                       last_seen = EXCLUDED.last_seen"#,
            )
            .bind(Uuid::new_v4())
            .bind(asset.id)
            .bind(&ident.kind)
            .bind(&ident.value)
            .bind(ident.first_seen)
            .bind(ident.last_seen)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(format!("upsert identity error: {e}")))?;
        }

        for ep in &asset.endpoints {
            let ep_tls: Vec<String> = ep.tls_versions.iter().map(|v| v.to_string()).collect();
            sqlx::query(
                r#"INSERT INTO asset_endpoints (id, asset_id, protocol, port, tls_versions, cipher_suites, first_seen, last_seen)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   ON CONFLICT (asset_id, protocol, port) DO UPDATE SET
                       tls_versions = EXCLUDED.tls_versions,
                       cipher_suites = EXCLUDED.cipher_suites,
                       last_seen = EXCLUDED.last_seen"#
            )
            .bind(Uuid::new_v4())
            .bind(asset.id)
            .bind(ep.protocol.to_string().to_lowercase())
            .bind(ep.port as i32)
            .bind(&ep_tls)
            .bind(&ep.cipher_suites)
            .bind(ep.first_seen)
            .bind(ep.last_seen)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(format!("upsert endpoint error: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<Asset>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, primary_name, addresses, hostnames, tls_versions, cipher_suites, certificate_fingerprints, active_findings_count, first_seen, last_seen, organization_id FROM assets ORDER BY last_seen DESC"
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list_all assets error: {e}")))?;

        let mut assets = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get("id");
            let identities = self.load_identities_for_asset(id).await?;
            let endpoints = self.load_endpoints_for_asset(id).await?;
            let raw_tls: Vec<String> = row.get("tls_versions");
            let tls_versions = raw_tls.into_iter().map(parse_tls_version).collect();

            assets.push(Asset {
                id,
                primary_name: row.get("primary_name"),
                addresses: row.get("addresses"),
                hostnames: row.get("hostnames"),
                identities,
                endpoints,
                tls_versions,
                cipher_suites: row.get("cipher_suites"),
                certificate_fingerprints: row.get("certificate_fingerprints"),
                active_findings_count: row.get::<i32, _>("active_findings_count") as usize,
                first_seen: row.get("first_seen"),
                last_seen: row.get("last_seen"),
                organization_id: row.try_get("organization_id").ok(),
            });
        }
        Ok(assets)
    }

    async fn save_drift_event(&self, event: DriftEvent) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO drift_events (id, asset_id, kind, title, description, previous_value, new_value, observed_at, session_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#
        )
        .bind(event.id)
        .bind(event.asset_id)
        .bind(drift_kind_to_string(&event.kind))
        .bind(&event.title)
        .bind(&event.description)
        .bind(&event.previous_value)
        .bind(&event.new_value)
        .bind(event.observed_at)
        .bind(event.session_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save_drift_event error: {e}")))?;
        Ok(())
    }

    async fn list_drift_events(
        &self,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<DriftEvent>, StorageError> {
        let rows = if let Some(aid) = asset_id {
            sqlx::query(
                "SELECT id, asset_id, kind, title, description, previous_value, new_value, observed_at, session_id FROM drift_events WHERE asset_id = $1 ORDER BY observed_at DESC LIMIT $2"
            )
            .bind(aid)
            .bind(limit as i64)
            .fetch_all(&*self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT id, asset_id, kind, title, description, previous_value, new_value, observed_at, session_id FROM drift_events ORDER BY observed_at DESC LIMIT $1"
            )
            .bind(limit as i64)
            .fetch_all(&*self.pool)
            .await
        }
        .map_err(|e| StorageError::Backend(format!("list_drift_events error: {e}")))?;

        let events = rows
            .into_iter()
            .map(|r| DriftEvent {
                id: r.get("id"),
                asset_id: r.get("asset_id"),
                kind: parse_drift_kind(r.get("kind")),
                title: r.get("title"),
                description: r.get("description"),
                previous_value: r.get("previous_value"),
                new_value: r.get("new_value"),
                observed_at: r.get("observed_at"),
                session_id: r.get("session_id"),
                assessment_id: r.try_get("assessment_id").ok(),
                domain: r.try_get("domain").ok(),
                organization_id: r.try_get("organization_id").ok(),
            })
            .collect();
        Ok(events)
    }
}

impl PostgresStorage {
    async fn load_identities_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Vec<AssetIdentity>, StorageError> {
        let rows = sqlx::query(
            "SELECT kind, value, first_seen, last_seen FROM asset_identities WHERE asset_id = $1 ORDER BY first_seen ASC"
        )
        .bind(asset_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("load_identities error: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| AssetIdentity {
                kind: r.get("kind"),
                value: r.get("value"),
                first_seen: r.get("first_seen"),
                last_seen: r.get("last_seen"),
            })
            .collect())
    }

    async fn load_endpoints_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Vec<AssetEndpoint>, StorageError> {
        let rows = sqlx::query(
            "SELECT protocol, port, tls_versions, cipher_suites, first_seen, last_seen FROM asset_endpoints WHERE asset_id = $1"
        )
        .bind(asset_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("load_endpoints error: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let proto_str: String = r.get("protocol");
                let raw_tls: Vec<String> = r.get("tls_versions");
                AssetEndpoint {
                    protocol: parse_email_protocol(&proto_str),
                    port: r.get::<i32, _>("port") as u16,
                    tls_versions: raw_tls.into_iter().map(parse_tls_version).collect(),
                    cipher_suites: r.get("cipher_suites"),
                    first_seen: r.get("first_seen"),
                    last_seen: r.get("last_seen"),
                }
            })
            .collect())
    }
}

#[async_trait]
impl CertificateRepository for PostgresStorage {
    async fn save(&self, cert: CertificateRecord) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        sqlx::query(
            r#"INSERT INTO certificates (sha256_fingerprint, subject, issuer, sans, not_before, not_after, first_seen, last_seen)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (sha256_fingerprint) DO UPDATE SET
                   last_seen = EXCLUDED.last_seen"#
        )
        .bind(&cert.sha256_fingerprint)
        .bind(&cert.subject)
        .bind(&cert.issuer)
        .bind(&cert.sans)
        .bind(cert.not_before)
        .bind(cert.not_after)
        .bind(cert.first_seen)
        .bind(cert.last_seen)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::Backend(format!("save certificate error: {e}")))?;

        for asset_id in &cert.associated_asset_ids {
            sqlx::query(
                r#"INSERT INTO asset_certificates (asset_id, certificate_fingerprint, first_seen, last_seen)
                   VALUES ($1, $2, $3, $4)
                   ON CONFLICT (asset_id, certificate_fingerprint) DO UPDATE SET
                       last_seen = EXCLUDED.last_seen"#
            )
            .bind(asset_id)
            .bind(&cert.sha256_fingerprint)
            .bind(cert.first_seen)
            .bind(cert.last_seen)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(format!("save asset_certificate error: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn find_by_fingerprint(
        &self,
        fp: &str,
    ) -> Result<Option<CertificateRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT sha256_fingerprint, subject, issuer, sans, not_before, not_after, first_seen, last_seen FROM certificates WHERE sha256_fingerprint = $1"
        )
        .bind(fp)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find_by_fingerprint error: {e}")))?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let asset_rows = sqlx::query(
            "SELECT asset_id FROM asset_certificates WHERE certificate_fingerprint = $1",
        )
        .bind(fp)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find cert assets error: {e}")))?;

        let associated_asset_ids = asset_rows.into_iter().map(|r| r.get("asset_id")).collect();

        Ok(Some(CertificateRecord {
            sha256_fingerprint: row.get("sha256_fingerprint"),
            subject: row.get("subject"),
            issuer: row.get("issuer"),
            sans: row.get("sans"),
            not_before: row.get("not_before"),
            not_after: row.get("not_after"),
            first_seen: row.get("first_seen"),
            last_seen: row.get("last_seen"),
            associated_asset_ids,
        }))
    }

    async fn list_all(&self) -> Result<Vec<CertificateRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT sha256_fingerprint, subject, issuer, sans, not_before, not_after, first_seen, last_seen FROM certificates ORDER BY last_seen DESC"
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list_all certificates error: {e}")))?;

        let mut certs = Vec::with_capacity(rows.len());
        for row in rows {
            let fp: String = row.get("sha256_fingerprint");
            let asset_rows = sqlx::query(
                "SELECT asset_id FROM asset_certificates WHERE certificate_fingerprint = $1",
            )
            .bind(&fp)
            .fetch_all(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(format!("list cert assets error: {e}")))?;

            certs.push(CertificateRecord {
                sha256_fingerprint: fp,
                subject: row.get("subject"),
                issuer: row.get("issuer"),
                sans: row.get("sans"),
                not_before: row.get("not_before"),
                not_after: row.get("not_after"),
                first_seen: row.get("first_seen"),
                last_seen: row.get("last_seen"),
                associated_asset_ids: asset_rows.into_iter().map(|r| r.get("asset_id")).collect(),
            });
        }
        Ok(certs)
    }

    async fn list_for_asset(&self, asset_id: Uuid) -> Result<Vec<CertificateRecord>, StorageError> {
        let rows = sqlx::query(
            r#"SELECT c.sha256_fingerprint, c.subject, c.issuer, c.sans, c.not_before, c.not_after, c.first_seen, c.last_seen
               FROM certificates c
               JOIN asset_certificates ac ON c.sha256_fingerprint = ac.certificate_fingerprint
               WHERE ac.asset_id = $1
               ORDER BY c.last_seen DESC"#
        )
        .bind(asset_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list_for_asset certs error: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| CertificateRecord {
                sha256_fingerprint: r.get("sha256_fingerprint"),
                subject: r.get("subject"),
                issuer: r.get("issuer"),
                sans: r.get("sans"),
                not_before: r.get("not_before"),
                not_after: r.get("not_after"),
                first_seen: r.get("first_seen"),
                last_seen: r.get("last_seen"),
                associated_asset_ids: vec![asset_id],
            })
            .collect())
    }
}

#[async_trait]
impl SensorRepository for PostgresStorage {
    async fn record_heartbeat(&self, heartbeat: SensorHeartbeat) -> Result<(), StorageError> {
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            r#"INSERT INTO sensors (id, site_id, hostname, version, mode, interface, status, last_seen, registered_at)
               VALUES ($1, $2, $3, $4, $5, $6, 'online', $7, $8)
               ON CONFLICT (id) DO UPDATE SET
                   site_id = EXCLUDED.site_id,
                   hostname = EXCLUDED.hostname,
                   version = EXCLUDED.version,
                   mode = EXCLUDED.mode,
                   interface = EXCLUDED.interface,
                   status = 'online',
                   last_seen = EXCLUDED.last_seen"#
        )
        .bind(&heartbeat.sensor_id)
        .bind(&heartbeat.site_id)
        .bind(&heartbeat.hostname)
        .bind(&heartbeat.version)
        .bind(&heartbeat.mode)
        .bind(&heartbeat.interface)
        .bind(now)
        .bind(now)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("record_heartbeat error: {e}")))?;

        Ok(())
    }

    async fn list_sensors(&self) -> Result<Vec<SensorRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, site_id, hostname, version, mode, interface, status, last_seen, registered_at FROM sensors ORDER BY last_seen DESC"
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list_sensors error: {e}")))?;

        let now = OffsetDateTime::now_utc();
        let sensors = rows
            .into_iter()
            .map(|r| {
                let last_seen: OffsetDateTime = r.get("last_seen");
                let diff = (now - last_seen).whole_seconds();
                let status = if diff > 120 {
                    SensorStatus::Offline
                } else if diff > 30 {
                    SensorStatus::Stale
                } else {
                    SensorStatus::Online
                };

                SensorRecord {
                    sensor_id: r.get("id"),
                    site_id: r.get("site_id"),
                    hostname: r.get("hostname"),
                    version: r.get("version"),
                    mode: r.get("mode"),
                    interface: r.get("interface"),
                    status,
                    last_seen,
                    registered_at: r.get("registered_at"),
                }
            })
            .collect();
        Ok(sensors)
    }

    async fn get_sensor(&self, sensor_id: &str) -> Result<Option<SensorRecord>, StorageError> {
        let sensors = self.list_sensors().await?;
        Ok(sensors.into_iter().find(|s| s.sensor_id == sensor_id))
    }
}

#[async_trait]
impl FindingRepository for PostgresStorage {
    async fn link_asset(&self, finding_id: Uuid, asset_id: Uuid) -> Result<(), StorageError> {
        let updated = sqlx::query(
            "UPDATE findings SET asset_id=$2 WHERE id=$1 AND (asset_id IS NULL OR asset_id=$2)",
        )
        .bind(finding_id)
        .bind(asset_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        if updated.rows_affected() == 0 {
            return Err(StorageError::Conflict(
                "finding missing or belongs to another asset".into(),
            ));
        }
        Ok(())
    }
    async fn save(&self, finding: Finding) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        sqlx::query(
            r#"INSERT INTO findings (id, rule_id, policy_name, policy_version, reference, severity, category, title, description, remediation, affected_count, first_seen, last_seen)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
               ON CONFLICT (id) DO UPDATE SET
                   affected_count = EXCLUDED.affected_count,
                   last_seen = EXCLUDED.last_seen"#
        )
        .bind(finding.id)
        .bind(&finding.rule_id)
        .bind(&finding.policy_name)
        .bind(&finding.policy_version)
        .bind(&finding.reference)
        .bind(finding_severity_to_string(&finding.severity))
        .bind(finding_category_to_string(&finding.category))
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.remediation)
        .bind(finding.affected_count as i32)
        .bind(finding.first_seen)
        .bind(finding.last_seen)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::Backend(format!("save finding error: {e}")))?;

        for ev in &finding.evidence {
            sqlx::query(
                r#"INSERT INTO finding_evidence (id, finding_id, session_id, observation_id, description)
                   SELECT $1, $2, $3, $4, $5 WHERE NOT EXISTS (
                       SELECT 1 FROM finding_evidence WHERE finding_id=$2
                       AND session_id IS NOT DISTINCT FROM $3 AND observation_id IS NOT DISTINCT FROM $4
                       AND description=$5
                   )"#
            )
            .bind(Uuid::new_v4())
            .bind(finding.id)
            .bind(ev.session_id)
            .bind(ev.observation_id)
            .bind(&ev.description)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(format!("save finding_evidence error: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<Finding>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, rule_id, policy_name, policy_version, reference, severity, category, title, description, remediation, affected_count, first_seen, last_seen FROM findings ORDER BY last_seen DESC"
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list_all findings error: {e}")))?;

        let mut findings = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get("id");
            let evidence = self.load_evidence_for_finding(id).await?;
            findings.push(Finding {
                id,
                rule_id: row.get("rule_id"),
                policy_name: row.get("policy_name"),
                policy_version: row.get("policy_version"),
                reference: row.get("reference"),
                severity: parse_severity(row.get("severity")),
                category: parse_category(row.get("category")),
                title: row.get("title"),
                description: row.get("description"),
                remediation: row.get("remediation"),
                affected_count: row.get::<i32, _>("affected_count") as u64,
                first_seen: row.get("first_seen"),
                last_seen: row.get("last_seen"),
                evidence,
                organization_id: row.try_get("organization_id").ok(),
            });
        }
        Ok(findings)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Finding>, StorageError> {
        let row = sqlx::query(
            "SELECT id, rule_id, policy_name, policy_version, reference, severity, category, title, description, remediation, affected_count, first_seen, last_seen, organization_id FROM findings WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find_by_id finding error: {e}")))?;

        let row = match row {
            Some(r) => r,
            None => return Ok(None),
        };

        let evidence = self.load_evidence_for_finding(id).await?;
        Ok(Some(Finding {
            id: row.get("id"),
            rule_id: row.get("rule_id"),
            policy_name: row.get("policy_name"),
            policy_version: row.get("policy_version"),
            reference: row.get("reference"),
            severity: parse_severity(row.get("severity")),
            category: parse_category(row.get("category")),
            title: row.get("title"),
            description: row.get("description"),
            remediation: row.get("remediation"),
            affected_count: row.get::<i32, _>("affected_count") as u64,
            first_seen: row.get("first_seen"),
            last_seen: row.get("last_seen"),
            evidence,
            organization_id: row.try_get("organization_id").ok(),
        }))
    }

    async fn list_for_session(&self, session_id: Uuid) -> Result<Vec<Finding>, StorageError> {
        let rows = sqlx::query(
            r#"SELECT DISTINCT f.id, f.rule_id, f.policy_name, f.policy_version, f.reference, f.severity, f.category, f.title, f.description, f.remediation, f.affected_count, f.first_seen, f.last_seen, f.organization_id
               FROM findings f
               JOIN finding_evidence fe ON f.id = fe.finding_id
               WHERE fe.session_id = $1
               ORDER BY f.last_seen DESC"#
        )
        .bind(session_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list_for_session findings error: {e}")))?;

        let mut findings = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get("id");
            let evidence = self.load_evidence_for_finding(id).await?;
            findings.push(Finding {
                id,
                rule_id: row.get("rule_id"),
                policy_name: row.get("policy_name"),
                policy_version: row.get("policy_version"),
                reference: row.get("reference"),
                severity: parse_severity(row.get("severity")),
                category: parse_category(row.get("category")),
                title: row.get("title"),
                description: row.get("description"),
                remediation: row.get("remediation"),
                affected_count: row.get::<i32, _>("affected_count") as u64,
                first_seen: row.get("first_seen"),
                last_seen: row.get("last_seen"),
                evidence,
                organization_id: row.try_get("organization_id").ok(),
            });
        }
        Ok(findings)
    }

    async fn list_for_asset(&self, asset_id: Uuid) -> Result<Vec<Finding>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, rule_id, policy_name, policy_version, reference, severity, category, title, description, remediation, affected_count, first_seen, last_seen, organization_id FROM findings WHERE asset_id = $1 ORDER BY last_seen DESC"
        )
        .bind(asset_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list_for_asset findings error: {e}")))?;

        let mut findings = Vec::with_capacity(rows.len());
        for row in rows {
            let id: Uuid = row.get("id");
            let evidence = self.load_evidence_for_finding(id).await?;
            findings.push(Finding {
                id,
                rule_id: row.get("rule_id"),
                policy_name: row.get("policy_name"),
                policy_version: row.get("policy_version"),
                reference: row.get("reference"),
                severity: parse_severity(row.get("severity")),
                category: parse_category(row.get("category")),
                title: row.get("title"),
                description: row.get("description"),
                remediation: row.get("remediation"),
                affected_count: row.get::<i32, _>("affected_count") as u64,
                first_seen: row.get("first_seen"),
                last_seen: row.get("last_seen"),
                evidence,
                organization_id: row.try_get("organization_id").ok(),
            });
        }
        Ok(findings)
    }
}

impl PostgresStorage {
    async fn load_evidence_for_finding(
        &self,
        finding_id: Uuid,
    ) -> Result<Vec<EvidenceRef>, StorageError> {
        let rows = sqlx::query(
            "SELECT DISTINCT session_id, observation_id, description FROM finding_evidence WHERE finding_id = $1 ORDER BY session_id, observation_id, description"
        )
        .bind(finding_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("load_evidence error: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| EvidenceRef {
                session_id: r.get("session_id"),
                observation_id: r.get("observation_id"),
                description: r.get("description"),
            })
            .collect())
    }
}

fn parse_tls_version(s: String) -> TlsVersion {
    match s.as_str() {
        "TLSv1.0" | "TLS1.0" => TlsVersion::Tls10,
        "TLSv1.1" | "TLS1.1" => TlsVersion::Tls11,
        "TLSv1.2" | "TLS1.2" => TlsVersion::Tls12,
        "TLSv1.3" | "TLS1.3" => TlsVersion::Tls13,
        other => TlsVersion::Unknown(other.to_string()),
    }
}

fn parse_email_protocol(s: &str) -> EmailProtocol {
    match s.to_lowercase().as_str() {
        "smtp" => EmailProtocol::Smtp,
        "imap" => EmailProtocol::Imap,
        "pop3" => EmailProtocol::Pop3,
        _ => EmailProtocol::Unknown,
    }
}

fn drift_kind_to_string(kind: &DriftKind) -> &'static str {
    match kind {
        DriftKind::NewTlsVersion => "new_tls_version",
        DriftKind::NewCipherSuite => "new_cipher_suite",
        DriftKind::KeyExchangeChanged => "key_exchange_changed",
        DriftKind::ForwardSecrecyLost => "forward_secrecy_lost",
        DriftKind::CertificateChanged => "certificate_changed",
        DriftKind::NewCertificateIssuer => "new_certificate_issuer",
        DriftKind::NewEndpoint => "new_endpoint",
        DriftKind::MxAdded => "mx_added",
        DriftKind::MxRemoved => "mx_removed",
        DriftKind::EndpointAdded => "endpoint_added",
        DriftKind::EndpointRemoved => "endpoint_removed",
        DriftKind::StartTlsLost => "starttls_lost",
        DriftKind::StartTlsRestored => "starttls_restored",
        DriftKind::LegacyTlsEnabled => "legacy_tls_enabled",
        DriftKind::LegacyTlsDisabled => "legacy_tls_disabled",
        DriftKind::ForwardSecrecyRestored => "forward_secrecy_restored",
        DriftKind::CertificateExpired => "certificate_expired",
        DriftKind::CertificateRenewed => "certificate_renewed",
        DriftKind::CertificateTrustChanged => "certificate_trust_changed",
        DriftKind::MtaStsChanged => "mta_sts_changed",
        DriftKind::DaneChanged => "dane_changed",
        DriftKind::TlsRptChanged => "tls_rpt_changed",
        DriftKind::FindingIntroduced => "finding_introduced",
        DriftKind::FindingResolved => "finding_resolved",
        DriftKind::PostureChanged => "posture_changed",
    }
}

fn parse_drift_kind(s: String) -> DriftKind {
    match s.as_str() {
        "new_tls_version" => DriftKind::NewTlsVersion,
        "new_cipher_suite" => DriftKind::NewCipherSuite,
        "key_exchange_changed" => DriftKind::KeyExchangeChanged,
        "forward_secrecy_lost" => DriftKind::ForwardSecrecyLost,
        "certificate_changed" => DriftKind::CertificateChanged,
        "new_certificate_issuer" => DriftKind::NewCertificateIssuer,
        "new_endpoint" => DriftKind::NewEndpoint,
        "mx_added" => DriftKind::MxAdded,
        "mx_removed" => DriftKind::MxRemoved,
        "endpoint_added" => DriftKind::EndpointAdded,
        "endpoint_removed" => DriftKind::EndpointRemoved,
        "starttls_lost" => DriftKind::StartTlsLost,
        "starttls_restored" => DriftKind::StartTlsRestored,
        "legacy_tls_enabled" => DriftKind::LegacyTlsEnabled,
        "legacy_tls_disabled" => DriftKind::LegacyTlsDisabled,
        "forward_secrecy_restored" => DriftKind::ForwardSecrecyRestored,
        "certificate_expired" => DriftKind::CertificateExpired,
        "certificate_renewed" => DriftKind::CertificateRenewed,
        "certificate_trust_changed" => DriftKind::CertificateTrustChanged,
        "mta_sts_changed" => DriftKind::MtaStsChanged,
        "dane_changed" => DriftKind::DaneChanged,
        "tls_rpt_changed" => DriftKind::TlsRptChanged,
        "finding_introduced" => DriftKind::FindingIntroduced,
        "finding_resolved" => DriftKind::FindingResolved,
        "posture_changed" => DriftKind::PostureChanged,
        _ => DriftKind::NewTlsVersion,
    }
}

fn finding_severity_to_string(s: &FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Critical => "critical",
        FindingSeverity::High => "high",
        FindingSeverity::Medium => "medium",
        FindingSeverity::Low => "low",
    }
}

fn parse_severity(s: String) -> FindingSeverity {
    match s.to_lowercase().as_str() {
        "critical" => FindingSeverity::Critical,
        "high" => FindingSeverity::High,
        "medium" => FindingSeverity::Medium,
        _ => FindingSeverity::Low,
    }
}

fn finding_category_to_string(c: &FindingCategory) -> &'static str {
    match c {
        FindingCategory::ProtocolDowngrade => "protocol_downgrade",
        FindingCategory::TlsConfiguration => "tls_configuration",
        FindingCategory::Certificate => "certificate",
        FindingCategory::AuthenticationExposed => "authentication_exposed",
        FindingCategory::PolicyViolation => "policy_violation",
    }
}

fn parse_category(s: String) -> FindingCategory {
    match s.to_lowercase().as_str() {
        "protocol_downgrade" => FindingCategory::ProtocolDowngrade,
        "tls_configuration" => FindingCategory::TlsConfiguration,
        "certificate" => FindingCategory::Certificate,
        "authentication_exposed" => FindingCategory::AuthenticationExposed,
        _ => FindingCategory::PolicyViolation,
    }
}

fn dnssec_to_string(d: &DnssecState) -> &'static str {
    match d {
        DnssecState::Secure => "secure",
        DnssecState::Insecure => "insecure",
        DnssecState::Bogus => "bogus",
        DnssecState::Indeterminate => "indeterminate",
    }
}

fn parse_dnssec(s: String) -> DnssecState {
    match s.to_lowercase().as_str() {
        "secure" => DnssecState::Secure,
        "insecure" => DnssecState::Insecure,
        "bogus" => DnssecState::Bogus,
        _ => DnssecState::Indeterminate,
    }
}

fn mta_sts_mode_to_string(m: &MtaStsMode) -> &'static str {
    match m {
        MtaStsMode::Enforce => "enforce",
        MtaStsMode::Testing => "testing",
        MtaStsMode::None => "none",
    }
}

fn parse_mta_sts_mode(s: String) -> MtaStsMode {
    match s.to_lowercase().as_str() {
        "enforce" => MtaStsMode::Enforce,
        "testing" => MtaStsMode::Testing,
        _ => MtaStsMode::None,
    }
}

fn investigation_status_to_string(s: &InvestigationStatus) -> &'static str {
    match s {
        InvestigationStatus::Open => "open",
        InvestigationStatus::UnderReview => "under_review",
        InvestigationStatus::Resolved => "resolved",
    }
}

fn parse_investigation_status(s: String) -> InvestigationStatus {
    match s.to_lowercase().as_str() {
        "under_review" => InvestigationStatus::UnderReview,
        "resolved" => InvestigationStatus::Resolved,
        _ => InvestigationStatus::Open,
    }
}

fn risk_to_string(r: &RiskLevel) -> &'static str {
    match r {
        RiskLevel::Low => "low",
        RiskLevel::Medium => "medium",
        RiskLevel::High => "high",
        RiskLevel::Critical => "critical",
    }
}

fn parse_risk(s: String) -> RiskLevel {
    match s.to_lowercase().as_str() {
        "critical" => RiskLevel::Critical,
        "high" => RiskLevel::High,
        "medium" => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

fn priority_to_string(p: &PriorityLevel) -> &'static str {
    match p {
        PriorityLevel::Low => "low",
        PriorityLevel::Normal => "normal",
        PriorityLevel::High => "high",
        PriorityLevel::Immediate => "immediate",
    }
}

fn parse_priority(s: String) -> PriorityLevel {
    match s.to_lowercase().as_str() {
        "immediate" => PriorityLevel::Immediate,
        "high" => PriorityLevel::High,
        "normal" => PriorityLevel::Normal,
        _ => PriorityLevel::Low,
    }
}

#[async_trait]
impl IntelligenceRepository for PostgresStorage {
    async fn save_mx_records(
        &self,
        domain: &str,
        records: &[MxRecord],
    ) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        sqlx::query("DELETE FROM mx_records WHERE domain = $1")
            .bind(domain)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        for r in records {
            sqlx::query(
                r#"INSERT INTO mx_records (id, domain, hostname, priority, resolved_ips, dnssec, first_seen, last_checked)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#
            )
            .bind(Uuid::new_v4())
            .bind(&r.domain)
            .bind(&r.hostname)
            .bind(r.priority as i32)
            .bind(&r.resolved_ips)
            .bind(dnssec_to_string(&r.dnssec))
            .bind(r.first_seen)
            .bind(r.last_checked)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get_mx_records(&self, domain: &str) -> Result<Vec<MxRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT domain, hostname, priority, resolved_ips, dnssec, first_seen, last_checked FROM mx_records WHERE domain = $1 ORDER BY priority ASC"
        )
        .bind(domain)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let records = rows
            .into_iter()
            .map(|row| MxRecord {
                domain: row.get("domain"),
                hostname: row.get("hostname"),
                priority: row.get::<i32, _>("priority") as u16,
                resolved_ips: row.get("resolved_ips"),
                dnssec: parse_dnssec(row.get("dnssec")),
                first_seen: row.get("first_seen"),
                last_checked: row.get("last_checked"),
            })
            .collect();
        Ok(records)
    }

    async fn save_tlsa_records(
        &self,
        domain: &str,
        records: &[TlsaRecord],
    ) -> Result<(), StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        sqlx::query("DELETE FROM tlsa_records WHERE domain = $1")
            .bind(domain)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        for r in records {
            sqlx::query(
                r#"INSERT INTO tlsa_records (id, domain, mx_host, port, usage, selector, matching_type, cert_association_data, dnssec, checked_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#
            )
            .bind(Uuid::new_v4())
            .bind(&r.domain)
            .bind(&r.mx_host)
            .bind(r.port as i32)
            .bind(r.usage as i32)
            .bind(r.selector as i32)
            .bind(r.matching_type as i32)
            .bind(&r.cert_association_data)
            .bind(dnssec_to_string(&r.dnssec))
            .bind(r.checked_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get_tlsa_records(&self, domain: &str) -> Result<Vec<TlsaRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT domain, mx_host, port, usage, selector, matching_type, cert_association_data, dnssec, checked_at FROM tlsa_records WHERE domain = $1"
        )
        .bind(domain)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let records = rows
            .into_iter()
            .map(|row| TlsaRecord {
                domain: row.get("domain"),
                mx_host: row.get("mx_host"),
                port: row.get::<i32, _>("port") as u16,
                usage: row.get::<i32, _>("usage") as u8,
                selector: row.get::<i32, _>("selector") as u8,
                matching_type: row.get::<i32, _>("matching_type") as u8,
                cert_association_data: row.get("cert_association_data"),
                dnssec: parse_dnssec(row.get("dnssec")),
                checked_at: row.get("checked_at"),
            })
            .collect();
        Ok(records)
    }

    async fn save_mta_sts_policy(&self, policy: &MtaStsPolicy) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO mta_sts_policies (domain, version, mode, mx_patterns, max_age_seconds, dnssec, checked_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (domain) DO UPDATE SET
                   version = EXCLUDED.version,
                   mode = EXCLUDED.mode,
                   mx_patterns = EXCLUDED.mx_patterns,
                   max_age_seconds = EXCLUDED.max_age_seconds,
                   dnssec = EXCLUDED.dnssec,
                   checked_at = EXCLUDED.checked_at"#
        )
        .bind(&policy.domain)
        .bind(&policy.version)
        .bind(mta_sts_mode_to_string(&policy.mode))
        .bind(&policy.mx_patterns)
        .bind(policy.max_age_seconds as i32)
        .bind(dnssec_to_string(&policy.dnssec))
        .bind(policy.checked_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get_mta_sts_policy(&self, domain: &str) -> Result<Option<MtaStsPolicy>, StorageError> {
        let row = sqlx::query(
            "SELECT domain, version, mode, mx_patterns, max_age_seconds, dnssec, checked_at FROM mta_sts_policies WHERE domain = $1"
        )
        .bind(domain)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(row.map(|r| MtaStsPolicy {
            domain: r.get("domain"),
            version: r.get("version"),
            mode: parse_mta_sts_mode(r.get("mode")),
            mx_patterns: r.get("mx_patterns"),
            max_age_seconds: r.get::<i32, _>("max_age_seconds") as u32,
            dnssec: parse_dnssec(r.get("dnssec")),
            checked_at: r.get("checked_at"),
        }))
    }

    async fn save_tls_rpt_policy(&self, policy: &TlsRptPolicy) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO tls_rpt_policies (domain, rua, checked_at)
               VALUES ($1, $2, $3)
               ON CONFLICT (domain) DO UPDATE SET
                   rua = EXCLUDED.rua,
                   checked_at = EXCLUDED.checked_at"#,
        )
        .bind(&policy.domain)
        .bind(&policy.rua)
        .bind(policy.checked_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get_tls_rpt_policy(&self, domain: &str) -> Result<Option<TlsRptPolicy>, StorageError> {
        let row =
            sqlx::query("SELECT domain, rua, checked_at FROM tls_rpt_policies WHERE domain = $1")
                .bind(domain)
                .fetch_optional(&*self.pool)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(row.map(|r| TlsRptPolicy {
            domain: r.get("domain"),
            rua: r.get("rua"),
            checked_at: r.get("checked_at"),
        }))
    }

    async fn save_tls_rpt_report(
        &self,
        report: &TlsRptAggregateReport,
    ) -> Result<(), StorageError> {
        let raw_json = serde_json::to_string(report).unwrap_or_default();
        sqlx::query(
            r#"INSERT INTO tls_rpt_reports (id, organization_name, policy_domain, start_date, end_date, successful_sessions, failed_sessions, raw_json, imported_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#
        )
        .bind(report.id)
        .bind(&report.organization_name)
        .bind(&report.policy_domain)
        .bind(report.start_date)
        .bind(report.end_date)
        .bind(report.successful_sessions as i64)
        .bind(report.failed_sessions as i64)
        .bind(raw_json)
        .bind(report.imported_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn list_tls_rpt_reports(
        &self,
        domain: Option<&str>,
        limit: usize,
    ) -> Result<Vec<TlsRptAggregateReport>, StorageError> {
        let rows = sqlx::query(
            "SELECT raw_json FROM tls_rpt_reports WHERE ($1::TEXT IS NULL OR policy_domain = $1) ORDER BY imported_at DESC LIMIT $2"
        )
        .bind(domain)
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let reports = rows
            .into_iter()
            .filter_map(|r| {
                let json: String = r.get("raw_json");
                serde_json::from_str(&json).ok()
            })
            .collect();
        Ok(reports)
    }

    async fn save_ct_certificates(
        &self,
        domain: &str,
        certs: &[CtCertificateRecord],
    ) -> Result<(), StorageError> {
        for c in certs {
            sqlx::query(
                r#"INSERT INTO ct_certificates (sha256_fingerprint, domain, names, issuer, not_before, not_after, ct_first_seen, observed_on_network, first_network_observation)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                   ON CONFLICT (sha256_fingerprint) DO UPDATE SET
                       observed_on_network = EXCLUDED.observed_on_network,
                       first_network_observation = COALESCE(ct_certificates.first_network_observation, EXCLUDED.first_network_observation)"#
            )
            .bind(&c.sha256_fingerprint)
            .bind(domain)
            .bind(&c.names)
            .bind(&c.issuer)
            .bind(c.not_before)
            .bind(c.not_after)
            .bind(c.ct_first_seen)
            .bind(c.observed_on_network)
            .bind(c.first_network_observation)
            .execute(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    async fn get_ct_certificates(
        &self,
        domain: &str,
    ) -> Result<Vec<CtCertificateRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT sha256_fingerprint, domain, names, issuer, not_before, not_after, ct_first_seen, observed_on_network, first_network_observation FROM ct_certificates WHERE domain = $1 ORDER BY ct_first_seen DESC"
        )
        .bind(domain)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let certs = rows
            .into_iter()
            .map(|r| CtCertificateRecord {
                sha256_fingerprint: r.get("sha256_fingerprint"),
                domain: r.get("domain"),
                names: r.get("names"),
                issuer: r.get("issuer"),
                not_before: r.get("not_before"),
                not_after: r.get("not_after"),
                ct_first_seen: r.get("ct_first_seen"),
                observed_on_network: r.get("observed_on_network"),
                first_network_observation: r.get("first_network_observation"),
            })
            .collect();
        Ok(certs)
    }

    async fn save_ct_event(&self, event: &CtIntelligenceEvent) -> Result<(), StorageError> {
        let kind_str = match event.kind {
            CtIntelligenceEventKind::NewCtCertificate => "new_certificate",
            CtIntelligenceEventKind::UnexpectedCtIssuer => "unexpected_issuer",
            CtIntelligenceEventKind::CtCertNowObservedOnMailServer => "now_observed",
        };
        sqlx::query(
            r#"INSERT INTO ct_events (id, domain, fingerprint, kind, title, description, observed_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#
        )
        .bind(event.id)
        .bind(&event.domain)
        .bind(&event.fingerprint)
        .bind(kind_str)
        .bind(&event.title)
        .bind(&event.description)
        .bind(event.observed_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn list_ct_events(
        &self,
        domain: Option<&str>,
        limit: usize,
    ) -> Result<Vec<CtIntelligenceEvent>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, domain, fingerprint, kind, title, description, observed_at FROM ct_events WHERE ($1::TEXT IS NULL OR domain = $1) ORDER BY observed_at DESC LIMIT $2"
        )
        .bind(domain)
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let events = rows
            .into_iter()
            .map(|r| {
                let kind_str: String = r.get("kind");
                let kind = match kind_str.as_str() {
                    "unexpected_issuer" => CtIntelligenceEventKind::UnexpectedCtIssuer,
                    "now_observed" => CtIntelligenceEventKind::CtCertNowObservedOnMailServer,
                    _ => CtIntelligenceEventKind::NewCtCertificate,
                };
                CtIntelligenceEvent {
                    id: r.get("id"),
                    domain: r.get("domain"),
                    fingerprint: r.get("fingerprint"),
                    kind,
                    title: r.get("title"),
                    description: r.get("description"),
                    observed_at: r.get("observed_at"),
                }
            })
            .collect();
        Ok(events)
    }

    async fn save_refresh_status(
        &self,
        status: &IntelligenceRefreshStatus,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO intelligence_refresh_status (domain, last_checked, next_check, last_success, last_error)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (domain) DO UPDATE SET
                   last_checked = EXCLUDED.last_checked,
                   next_check = EXCLUDED.next_check,
                   last_success = EXCLUDED.last_success,
                   last_error = EXCLUDED.last_error"#
        )
        .bind(&status.domain)
        .bind(status.last_checked)
        .bind(status.next_check)
        .bind(status.last_success)
        .bind(&status.last_error)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get_refresh_status(
        &self,
        domain: &str,
    ) -> Result<Option<IntelligenceRefreshStatus>, StorageError> {
        let row = sqlx::query(
            "SELECT domain, last_checked, next_check, last_success, last_error FROM intelligence_refresh_status WHERE domain = $1"
        )
        .bind(domain)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(row.map(|r| IntelligenceRefreshStatus {
            domain: r.get("domain"),
            last_checked: r.get("last_checked"),
            next_check: r.get("next_check"),
            last_success: r.get("last_success"),
            last_error: r.get("last_error"),
        }))
    }

    async fn list_due_refreshes(&self) -> Result<Vec<String>, StorageError> {
        let rows = sqlx::query("SELECT domain FROM intelligence_refresh_status WHERE next_check IS NOT NULL AND next_check <= NOW()")
            .fetch_all(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(rows.into_iter().map(|r| r.get("domain")).collect())
    }
}

#[async_trait]
impl BaselineRepository for PostgresStorage {
    async fn save_baseline(&self, baseline: &AssetBaseline) -> Result<(), StorageError> {
        let tls_dist = serde_json::to_value(&baseline.tls_version_distribution).unwrap_or_default();
        let cipher_dist = serde_json::to_value(&baseline.cipher_distribution).unwrap_or_default();
        let kx_dist = serde_json::to_value(&baseline.key_exchange_distribution).unwrap_or_default();
        let ports: Vec<i32> = baseline.ports.iter().map(|p| *p as i32).collect();

        sqlx::query(
            r#"INSERT INTO asset_baselines (
                   asset_id, sample_count, window_start, window_end, generated_at, coverage,
                   tls_version_distribution, cipher_distribution, key_exchange_distribution,
                   certificate_fingerprints, certificate_issuers, starttls_success_rate,
                   handshake_failure_rate, peer_set, ports, session_frequency_per_hour
               ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
               ON CONFLICT (asset_id) DO UPDATE SET
                   sample_count = EXCLUDED.sample_count,
                   window_start = EXCLUDED.window_start,
                   window_end = EXCLUDED.window_end,
                   generated_at = EXCLUDED.generated_at,
                   coverage = EXCLUDED.coverage,
                   tls_version_distribution = EXCLUDED.tls_version_distribution,
                   cipher_distribution = EXCLUDED.cipher_distribution,
                   key_exchange_distribution = EXCLUDED.key_exchange_distribution,
                   certificate_fingerprints = EXCLUDED.certificate_fingerprints,
                   certificate_issuers = EXCLUDED.certificate_issuers,
                   starttls_success_rate = EXCLUDED.starttls_success_rate,
                   handshake_failure_rate = EXCLUDED.handshake_failure_rate,
                   peer_set = EXCLUDED.peer_set,
                   ports = EXCLUDED.ports,
                   session_frequency_per_hour = EXCLUDED.session_frequency_per_hour"#,
        )
        .bind(baseline.asset_id)
        .bind(baseline.sample_count as i64)
        .bind(baseline.window_start)
        .bind(baseline.window_end)
        .bind(baseline.generated_at)
        .bind(baseline.coverage)
        .bind(tls_dist)
        .bind(cipher_dist)
        .bind(kx_dist)
        .bind(&baseline.certificate_fingerprints)
        .bind(&baseline.certificate_issuers)
        .bind(baseline.starttls_success_rate)
        .bind(baseline.handshake_failure_rate)
        .bind(&baseline.peer_set)
        .bind(ports)
        .bind(baseline.session_frequency_per_hour)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get_baseline(&self, asset_id: Uuid) -> Result<Option<AssetBaseline>, StorageError> {
        let row = sqlx::query(
            r#"SELECT asset_id, sample_count, window_start, window_end, generated_at, coverage,
                      tls_version_distribution, cipher_distribution, key_exchange_distribution,
                      certificate_fingerprints, certificate_issuers, starttls_success_rate,
                      handshake_failure_rate, peer_set, ports, session_frequency_per_hour
               FROM asset_baselines WHERE asset_id = $1"#,
        )
        .bind(asset_id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        if let Some(r) = row {
            let tls_dist_val: serde_json::Value = r.get("tls_version_distribution");
            let cipher_dist_val: serde_json::Value = r.get("cipher_distribution");
            let kx_dist_val: serde_json::Value = r.get("key_exchange_distribution");
            let ports_i32: Vec<i32> = r.get("ports");

            Ok(Some(AssetBaseline {
                asset_id: r.get("asset_id"),
                sample_count: r.get::<i64, _>("sample_count") as u64,
                window_start: r.get("window_start"),
                window_end: r.get("window_end"),
                generated_at: r.get("generated_at"),
                coverage: r.get("coverage"),
                tls_version_distribution: serde_json::from_value(tls_dist_val).unwrap_or_default(),
                cipher_distribution: serde_json::from_value(cipher_dist_val).unwrap_or_default(),
                key_exchange_distribution: serde_json::from_value(kx_dist_val).unwrap_or_default(),
                certificate_fingerprints: r.get("certificate_fingerprints"),
                certificate_issuers: r.get("certificate_issuers"),
                starttls_success_rate: r.get("starttls_success_rate"),
                handshake_failure_rate: r.get("handshake_failure_rate"),
                peer_set: r.get("peer_set"),
                ports: ports_i32.into_iter().map(|p| p as u16).collect(),
                session_frequency_per_hour: r.get("session_frequency_per_hour"),
            }))
        } else {
            Ok(None)
        }
    }

    async fn save_anomaly(&self, anomaly: &AnomalySignal) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO anomaly_signals (id, asset_id, signal, title, current_value, baseline_value, deviation, confidence, evidence, observed_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#
        )
        .bind(anomaly.id)
        .bind(anomaly.asset_id)
        .bind(&anomaly.signal)
        .bind(&anomaly.title)
        .bind(&anomaly.current_value)
        .bind(&anomaly.baseline_value)
        .bind(anomaly.deviation)
        .bind(anomaly.confidence)
        .bind(&anomaly.evidence)
        .bind(anomaly.observed_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn list_anomalies(
        &self,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<AnomalySignal>, StorageError> {
        let rows = sqlx::query(
            r#"SELECT id, asset_id, signal, title, current_value, baseline_value, deviation, confidence, evidence, observed_at
               FROM anomaly_signals WHERE ($1::UUID IS NULL OR asset_id = $1)
               ORDER BY observed_at DESC LIMIT $2"#
        )
        .bind(asset_id)
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let anomalies = rows
            .into_iter()
            .map(|r| AnomalySignal {
                id: r.get("id"),
                asset_id: r.get("asset_id"),
                signal: r.get("signal"),
                title: r.get("title"),
                current_value: r.get("current_value"),
                baseline_value: r.get("baseline_value"),
                deviation: r.get("deviation"),
                confidence: r.get("confidence"),
                evidence: r.get("evidence"),
                observed_at: r.get("observed_at"),
            })
            .collect();
        Ok(anomalies)
    }
}

#[async_trait]
impl InvestigationRepository for PostgresStorage {
    async fn attach_probe(&self, run: &ProbeRun) -> Result<(), StorageError> {
        if let Some(id) = run.investigation_id {
            sqlx::query("UPDATE investigations SET external_intelligence = jsonb_set(COALESCE(external_intelligence, '{}'::jsonb), '{active_verifications}', COALESCE(external_intelligence->'active_verifications', '{}'::jsonb) || jsonb_build_object($2::text, $3::jsonb)) WHERE id=$1 AND asset_id=$4")
                .bind(id).bind(run.id.to_string()).bind(serde_json::to_value(run).map_err(|e| StorageError::Backend(e.to_string()))?).bind(run.asset_id)
                .execute(&*self.pool).await.map_err(|e| StorageError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    async fn save(&self, inv: &Investigation) -> Result<(), StorageError> {
        let jev_val = inv
            .jev_decision
            .as_ref()
            .map(|v| serde_json::to_value(v).unwrap_or_default());
        sqlx::query(
            r#"INSERT INTO investigations (id, asset_id, title, summary, status, risk, priority, finding_ids, drift_event_ids, anomaly_ids, external_intelligence, jev_decision, first_observed, last_observed)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
               ON CONFLICT (id) DO UPDATE SET
                   title = EXCLUDED.title,
                   summary = EXCLUDED.summary,
                   risk = EXCLUDED.risk,
                   priority = EXCLUDED.priority,
                   finding_ids = ARRAY(SELECT DISTINCT x FROM unnest(investigations.finding_ids || EXCLUDED.finding_ids) x ORDER BY x),
                   drift_event_ids = ARRAY(SELECT DISTINCT x FROM unnest(investigations.drift_event_ids || EXCLUDED.drift_event_ids) x ORDER BY x),
                   anomaly_ids = ARRAY(SELECT DISTINCT x FROM unnest(investigations.anomaly_ids || EXCLUDED.anomaly_ids) x ORDER BY x),
                   external_intelligence = investigations.external_intelligence || EXCLUDED.external_intelligence ||
                       jsonb_build_object('active_verifications', COALESCE(investigations.external_intelligence->'active_verifications', '{}'::jsonb) || COALESCE(EXCLUDED.external_intelligence->'active_verifications', '{}'::jsonb)),
                   jev_decision = EXCLUDED.jev_decision,
                   first_observed = LEAST(investigations.first_observed, EXCLUDED.first_observed),
                   last_observed = GREATEST(investigations.last_observed, EXCLUDED.last_observed)"#
        )
        .bind(inv.id)
        .bind(inv.asset_id)
        .bind(&inv.title)
        .bind(&inv.summary)
        .bind(investigation_status_to_string(&inv.status))
        .bind(risk_to_string(&inv.risk))
        .bind(priority_to_string(&inv.priority))
        .bind(&inv.finding_ids)
        .bind(&inv.drift_event_ids)
        .bind(&inv.anomaly_ids)
        .bind(&inv.external_intelligence)
        .bind(jev_val)
        .bind(inv.first_observed)
        .bind(inv.last_observed)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Investigation>, StorageError> {
        let row = sqlx::query(
            r#"SELECT id, asset_id, title, summary, status, risk, priority, finding_ids, drift_event_ids, anomaly_ids, external_intelligence, jev_decision, first_observed, last_observed
               FROM investigations WHERE id = $1"#
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(row.map(|r| {
            let jev_val: Option<serde_json::Value> = r.get("jev_decision");
            Investigation {
                id: r.get("id"),
                asset_id: r.get("asset_id"),
                title: r.get("title"),
                summary: r.get("summary"),
                status: parse_investigation_status(r.get("status")),
                risk: parse_risk(r.get("risk")),
                priority: parse_priority(r.get("priority")),
                finding_ids: r.get("finding_ids"),
                drift_event_ids: r.get("drift_event_ids"),
                anomaly_ids: r.get("anomaly_ids"),
                external_intelligence: r.get("external_intelligence"),
                jev_decision: jev_val.and_then(|v| serde_json::from_value(v).ok()),
                first_observed: r.get("first_observed"),
                last_observed: r.get("last_observed"),
            }
        }))
    }

    async fn list_all(&self, limit: usize) -> Result<Vec<Investigation>, StorageError> {
        let rows = sqlx::query(
            r#"SELECT id, asset_id, title, summary, status, risk, priority, finding_ids, drift_event_ids, anomaly_ids, external_intelligence, jev_decision, first_observed, last_observed
               FROM investigations ORDER BY last_observed DESC LIMIT $1"#
        )
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let items = rows
            .into_iter()
            .map(|r| {
                let jev_val: Option<serde_json::Value> = r.get("jev_decision");
                Investigation {
                    id: r.get("id"),
                    asset_id: r.get("asset_id"),
                    title: r.get("title"),
                    summary: r.get("summary"),
                    status: parse_investigation_status(r.get("status")),
                    risk: parse_risk(r.get("risk")),
                    priority: parse_priority(r.get("priority")),
                    finding_ids: r.get("finding_ids"),
                    drift_event_ids: r.get("drift_event_ids"),
                    anomaly_ids: r.get("anomaly_ids"),
                    external_intelligence: r.get("external_intelligence"),
                    jev_decision: jev_val.and_then(|v| serde_json::from_value(v).ok()),
                    first_observed: r.get("first_observed"),
                    last_observed: r.get("last_observed"),
                }
            })
            .collect();
        Ok(items)
    }

    async fn list_for_asset(&self, asset_id: Uuid) -> Result<Vec<Investigation>, StorageError> {
        let rows = sqlx::query(
            r#"SELECT id, asset_id, title, summary, status, risk, priority, finding_ids, drift_event_ids, anomaly_ids, external_intelligence, jev_decision, first_observed, last_observed
               FROM investigations WHERE asset_id = $1 ORDER BY last_observed DESC"#
        )
        .bind(asset_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let items = rows
            .into_iter()
            .map(|r| {
                let jev_val: Option<serde_json::Value> = r.get("jev_decision");
                Investigation {
                    id: r.get("id"),
                    asset_id: r.get("asset_id"),
                    title: r.get("title"),
                    summary: r.get("summary"),
                    status: parse_investigation_status(r.get("status")),
                    risk: parse_risk(r.get("risk")),
                    priority: parse_priority(r.get("priority")),
                    finding_ids: r.get("finding_ids"),
                    drift_event_ids: r.get("drift_event_ids"),
                    anomaly_ids: r.get("anomaly_ids"),
                    external_intelligence: r.get("external_intelligence"),
                    jev_decision: jev_val.and_then(|v| serde_json::from_value(v).ok()),
                    first_observed: r.get("first_observed"),
                    last_observed: r.get("last_observed"),
                }
            })
            .collect();
        Ok(items)
    }

    async fn update_status(
        &self,
        id: Uuid,
        status: InvestigationStatus,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE investigations SET status = $1, last_observed = NOW() WHERE id = $2")
            .bind(investigation_status_to_string(&status))
            .bind(id)
            .execute(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl DecisionRepository for PostgresStorage {
    async fn save_record(&self, r: &DecisionRecord) -> Result<(), StorageError> {
        sqlx::query(
            r#"INSERT INTO decision_records (id, session_id, asset_id, provider, model, risk, anomalous, human_review, priority, confidence, reasons, provider_info, latency_ms, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)"#
        )
        .bind(r.id)
        .bind(r.session_id)
        .bind(r.asset_id)
        .bind(&r.provider)
        .bind(&r.model)
        .bind(risk_to_string(&r.decision.risk))
        .bind(r.decision.anomalous)
        .bind(r.decision.human_review)
        .bind(priority_to_string(&r.decision.priority))
        .bind(r.decision.confidence)
        .bind(&r.decision.reasons)
        .bind(&r.decision.provider_info)
        .bind(r.latency_ms as i64)
        .bind(r.created_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn list_recent(&self, limit: usize) -> Result<Vec<DecisionRecord>, StorageError> {
        let rows = sqlx::query(
            r#"SELECT id, session_id, asset_id, provider, model, risk, anomalous, human_review, priority, confidence, reasons, provider_info, latency_ms, created_at
               FROM decision_records ORDER BY created_at DESC LIMIT $1"#
        )
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        let items = rows
            .into_iter()
            .map(|r| DecisionRecord {
                id: r.get("id"),
                session_id: r.get("session_id"),
                asset_id: r.get("asset_id"),
                provider: r.get("provider"),
                model: r.get("model"),
                decision: DecisionResult {
                    risk: parse_risk(r.get("risk")),
                    anomalous: r.get("anomalous"),
                    human_review: r.get("human_review"),
                    priority: parse_priority(r.get("priority")),
                    confidence: r.get("confidence"),
                    provider_info: r.get("provider_info"),
                    reasons: r.get("reasons"),
                },
                latency_ms: r.get::<i64, _>("latency_ms") as u64,
                created_at: r.get("created_at"),
            })
            .collect();
        Ok(items)
    }
}

#[async_trait]
impl ProbeRepository for PostgresStorage {
    async fn reserve(&self, run: &ProbeRun, cooldown_seconds: u64) -> Result<bool, StorageError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(&run.target)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM probe_runs WHERE target=$1 AND (finished_at IS NULL OR finished_at > $2))")
            .bind(&run.target).bind(run.started_at - time::Duration::seconds(cooldown_seconds as i64)).fetch_one(&mut *tx).await.map_err(|e| StorageError::Backend(e.to_string()))?;
        if blocked {
            return Ok(false);
        }
        let result_json = run
            .result
            .as_ref()
            .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null));
        let mismatches_json = serde_json::to_value(&run.perspective_mismatches)
            .unwrap_or(serde_json::Value::Array(vec![]));

        sqlx::query(
            r#"INSERT INTO probe_runs
               (id, asset_id, target, protocol, port, trigger, investigation_id,
                started_at, finished_at, outcome, result, perspective_mismatches, has_mismatch, remediation_id, verification_condition)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
               ON CONFLICT (id) DO UPDATE SET
                   finished_at = EXCLUDED.finished_at,
                   outcome = EXCLUDED.outcome,
                   result = EXCLUDED.result,
                   perspective_mismatches = EXCLUDED.perspective_mismatches,
                   has_mismatch = EXCLUDED.has_mismatch"#,
        )
        .bind(run.id)
        .bind(run.asset_id)
        .bind(&run.target)
        .bind(format!("{}", run.protocol).to_lowercase())
        .bind(i32::from(run.port))
        .bind(probe_trigger_to_str(&run.trigger))
        .bind(run.investigation_id)
        .bind(run.started_at)
        .bind(run.finished_at)
        .bind(probe_outcome_to_str(&run.outcome))
        .bind(result_json)
        .bind(mismatches_json)
        .bind(run.has_mismatch)
        .bind(run.remediation_id)
        .bind(run.verification_condition.map(|c| serde_json::to_value(c).expect("enum serialization")))
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::Backend(format!("save probe_run error: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(true)
    }

    async fn unfinished(&self) -> Result<Vec<ProbeRun>, StorageError> {
        let rows = sqlx::query("SELECT * FROM probe_runs WHERE finished_at IS NULL")
            .fetch_all(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(rows.into_iter().map(probe_run_from_row).collect())
    }
    async fn save(&self, run: &ProbeRun) -> Result<(), StorageError> {
        let result_json = run
            .result
            .as_ref()
            .map(|r| serde_json::to_value(r).unwrap_or(serde_json::Value::Null));
        let mismatches_json = serde_json::to_value(&run.perspective_mismatches)
            .unwrap_or(serde_json::Value::Array(vec![]));

        sqlx::query(
            r#"INSERT INTO probe_runs
               (id, asset_id, target, protocol, port, trigger, investigation_id,
                started_at, finished_at, outcome, result, perspective_mismatches, has_mismatch, remediation_id, verification_condition)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
               ON CONFLICT (id) DO UPDATE SET
                   finished_at = EXCLUDED.finished_at,
                   outcome = EXCLUDED.outcome,
                   result = EXCLUDED.result,
                   perspective_mismatches = EXCLUDED.perspective_mismatches,
                   has_mismatch = EXCLUDED.has_mismatch"#,
        )
        .bind(run.id)
        .bind(run.asset_id)
        .bind(&run.target)
        .bind(format!("{}", run.protocol).to_lowercase())
        .bind(i32::from(run.port))
        .bind(probe_trigger_to_str(&run.trigger))
        .bind(run.investigation_id)
        .bind(run.started_at)
        .bind(run.finished_at)
        .bind(probe_outcome_to_str(&run.outcome))
        .bind(result_json)
        .bind(mismatches_json)
        .bind(run.has_mismatch)
        .bind(run.remediation_id)
        .bind(run.verification_condition.map(|c| serde_json::to_value(c).expect("enum serialization")))
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save probe_run error: {e}")))?;
        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ProbeRun>, StorageError> {
        let row = sqlx::query(
            "SELECT id, asset_id, target, protocol, port, trigger, investigation_id,
                    started_at, finished_at, outcome, result, perspective_mismatches, has_mismatch, remediation_id, verification_condition
             FROM probe_runs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(row.map(probe_run_from_row))
    }

    async fn list_for_asset(
        &self,
        asset_id: Uuid,
        limit: usize,
    ) -> Result<Vec<ProbeRun>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, asset_id, target, protocol, port, trigger, investigation_id,
                    started_at, finished_at, outcome, result, perspective_mismatches, has_mismatch, remediation_id, verification_condition
             FROM probe_runs WHERE asset_id = $1 ORDER BY started_at DESC LIMIT $2",
        )
        .bind(asset_id)
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(rows.into_iter().map(probe_run_from_row).collect())
    }

    async fn list_recent(&self, limit: usize) -> Result<Vec<ProbeRun>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, asset_id, target, protocol, port, trigger, investigation_id,
                    started_at, finished_at, outcome, result, perspective_mismatches, has_mismatch, remediation_id, verification_condition
             FROM probe_runs ORDER BY started_at DESC LIMIT $1",
        )
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(rows.into_iter().map(probe_run_from_row).collect())
    }

    async fn latest_for_target(
        &self,
        asset_id: Uuid,
        target: &str,
    ) -> Result<Option<ProbeRun>, StorageError> {
        let row = sqlx::query(
            "SELECT id, asset_id, target, protocol, port, trigger, investigation_id,
                    started_at, finished_at, outcome, result, perspective_mismatches, has_mismatch, remediation_id, verification_condition
             FROM probe_runs
             WHERE asset_id = $1 AND target = $2
             ORDER BY started_at DESC LIMIT 1",
        )
        .bind(asset_id)
        .bind(target)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(row.map(probe_run_from_row))
    }

    async fn update(&self, run: &ProbeRun) -> Result<(), StorageError> {
        ProbeRepository::save(self, run).await
    }
}

#[async_trait]
impl TrainingRecordRepository for PostgresStorage {
    async fn attach_remediation_outcome(
        &self,
        id: Uuid,
        outcome: &mailent_domain::RemediationTrainingOutcome,
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE training_records SET remediation_outcomes = remediation_outcomes || jsonb_build_object($2::text, $3::jsonb) WHERE id=$1 AND NOT remediation_outcomes ? $2")
            .bind(id).bind(outcome.request_id.to_string()).bind(serde_json::to_value(outcome).map_err(|e| StorageError::Backend(e.to_string()))?)
            .execute(&*self.pool).await.map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn save(&self, record: &TrainingRecord) -> Result<(), StorageError> {
        let features_json = serde_json::to_value(&record.features)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let automated_json = record
            .automated_label
            .as_ref()
            .map(|l| serde_json::to_value(l).unwrap_or_default());
        let analyst_json = record
            .analyst_label
            .as_ref()
            .map(|l| serde_json::to_value(l).unwrap_or_default());

        let inserted = sqlx::query(
            r#"INSERT INTO training_records
               (id, investigation_id, asset_id, feature_schema_version, captured_at, features, automated_label, analyst_label, labeled_at)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(record.id)
        .bind(record.investigation_id)
        .bind(record.asset_id)
        .bind(record.feature_schema_version as i32)
        .bind(record.captured_at)
        .bind(features_json)
        .bind(automated_json)
        .bind(analyst_json)
        .bind(record.labeled_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        if inserted.rows_affected() == 0 {
            let stored = TrainingRecordRepository::find_by_id(self, record.id)
                .await?
                .ok_or_else(|| StorageError::NotFound(record.id.to_string()))?;
            if !stored.same_snapshot(record) {
                return Err(StorageError::Conflict(
                    "training features are immutable".into(),
                ));
            }
        }
        Ok(())
    }

    async fn list_recent(
        &self,
        investigation_id: Option<Uuid>,
        asset_id: Option<Uuid>,
        limit: usize,
    ) -> Result<Vec<TrainingRecord>, StorageError> {
        let rows = sqlx::query(
            r#"SELECT id, investigation_id, asset_id, feature_schema_version, captured_at, features, automated_label, analyst_label, labeled_at, remediation_outcomes
               FROM training_records
               WHERE ($1::UUID IS NULL OR investigation_id = $1)
                 AND ($2::UUID IS NULL OR asset_id = $2)
               ORDER BY captured_at DESC LIMIT $3"#,
        )
        .bind(investigation_id)
        .bind(asset_id)
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        rows.into_iter().map(training_record_from_row).collect()
    }

    async fn list_unlabeled(&self, limit: usize) -> Result<Vec<TrainingRecord>, StorageError> {
        let rows = sqlx::query(
            r#"SELECT id, investigation_id, asset_id, feature_schema_version, captured_at, features, automated_label, analyst_label, labeled_at, remediation_outcomes
               FROM training_records WHERE analyst_label IS NULL
               ORDER BY captured_at DESC LIMIT $1"#,
        )
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        rows.into_iter().map(training_record_from_row).collect()
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<TrainingRecord>, StorageError> {
        let row = sqlx::query(
            r#"SELECT id, investigation_id, asset_id, feature_schema_version, captured_at, features, automated_label, analyst_label, labeled_at, remediation_outcomes
               FROM training_records WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        row.map(training_record_from_row).transpose()
    }

    async fn attach_analyst_label(
        &self,
        id: Uuid,
        label: &mailent_domain::AnalystLabel,
    ) -> Result<(), StorageError> {
        let label_json =
            serde_json::to_value(label).map_err(|e| StorageError::Backend(e.to_string()))?;
        let updated = sqlx::query(
            r#"UPDATE training_records
               SET analyst_label = $2, labeled_at = now()
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(label_json)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        if updated.rows_affected() == 0 {
            return Err(StorageError::NotFound(format!(
                "training record {id} not found"
            )));
        }
        Ok(())
    }
}

fn training_record_from_row(r: sqlx::postgres::PgRow) -> Result<TrainingRecord, StorageError> {
    let decode = |error: serde_json::Error| {
        StorageError::Backend(format!("Invalid stored training evidence: {error}"))
    };
    Ok(TrainingRecord {
        id: r.get("id"),
        investigation_id: r.get("investigation_id"),
        asset_id: r.get("asset_id"),
        feature_schema_version: r.get::<i32, _>("feature_schema_version") as u32,
        captured_at: r.get("captured_at"),
        features: serde_json::from_value(r.get("features")).map_err(decode)?,
        automated_label: r
            .get::<Option<serde_json::Value>, _>("automated_label")
            .map(serde_json::from_value)
            .transpose()
            .map_err(decode)?,
        analyst_label: r
            .get::<Option<serde_json::Value>, _>("analyst_label")
            .map(serde_json::from_value)
            .transpose()
            .map_err(decode)?,
        labeled_at: r.get("labeled_at"),
        remediation_outcomes: serde_json::from_value(r.get("remediation_outcomes"))
            .map_err(decode)?,
    })
}

fn probe_trigger_to_str(t: &ProbeTrigger) -> &'static str {
    match t {
        ProbeTrigger::ManualAnalyst => "manual_analyst",
        ProbeTrigger::InternalExternalInconsistency => "internal_external_inconsistency",
        ProbeTrigger::CertificateChange => "certificate_change",
        ProbeTrigger::StartTlsRegression => "starttls_regression",
        ProbeTrigger::Scheduled => "scheduled",
        ProbeTrigger::DriftTriggered => "drift_triggered",
        ProbeTrigger::RemediationVerification => "remediation_verification",
    }
}

fn probe_outcome_to_str(o: &ProbeOutcome) -> &'static str {
    match o {
        ProbeOutcome::Success => "success",
        ProbeOutcome::Timeout => "timeout",
        ProbeOutcome::ConnectionRefused => "connection_refused",
        ProbeOutcome::HandshakeError => "handshake_error",
        ProbeOutcome::ScopeRejected => "scope_rejected",
        ProbeOutcome::InternalError => "internal_error",
    }
}

fn str_to_probe_trigger(s: &str) -> ProbeTrigger {
    match s {
        "manual_analyst" => ProbeTrigger::ManualAnalyst,
        "internal_external_inconsistency" => ProbeTrigger::InternalExternalInconsistency,
        "certificate_change" => ProbeTrigger::CertificateChange,
        "starttls_regression" => ProbeTrigger::StartTlsRegression,
        "drift_triggered" => ProbeTrigger::DriftTriggered,
        "remediation_verification" => ProbeTrigger::RemediationVerification,
        _ => ProbeTrigger::Scheduled,
    }
}

fn str_to_probe_outcome(s: &str) -> ProbeOutcome {
    match s {
        "success" => ProbeOutcome::Success,
        "timeout" => ProbeOutcome::Timeout,
        "connection_refused" => ProbeOutcome::ConnectionRefused,
        "handshake_error" => ProbeOutcome::HandshakeError,
        "scope_rejected" => ProbeOutcome::ScopeRejected,
        _ => ProbeOutcome::InternalError,
    }
}

fn probe_run_from_row(r: sqlx::postgres::PgRow) -> ProbeRun {
    use sqlx::Row;
    let result: Option<ProbeResult> = r
        .get::<Option<serde_json::Value>, _>("result")
        .and_then(|v| serde_json::from_value(v).ok());
    let mismatches: Vec<PerspectiveMismatch> = r
        .get::<serde_json::Value, _>("perspective_mismatches")
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    let protocol_str: String = r.get("protocol");
    let trigger_str: String = r.get("trigger");
    let outcome_str: String = r.get("outcome");
    ProbeRun {
        remediation_id: r.get("remediation_id"),
        verification_condition: r
            .get::<Option<serde_json::Value>, _>("verification_condition")
            .and_then(|v| serde_json::from_value(v).ok()),
        id: r.get("id"),
        asset_id: r.get("asset_id"),
        target: r.get("target"),
        protocol: match protocol_str.as_str() {
            "imap" => EmailProtocol::Imap,
            "pop3" => EmailProtocol::Pop3,
            _ => EmailProtocol::Smtp,
        },
        port: r.get::<i32, _>("port") as u16,
        trigger: str_to_probe_trigger(&trigger_str),
        investigation_id: r.get("investigation_id"),
        started_at: r.get("started_at"),
        finished_at: r.get("finished_at"),
        outcome: str_to_probe_outcome(&outcome_str),
        result,
        perspective_mismatches: mismatches,
        has_mismatch: r.get("has_mismatch"),
    }
}

#[async_trait]
impl crate::repository::RemediationRepository for PostgresStorage {
    async fn create(
        &self,
        record: &mailent_domain::RemediationRecord,
    ) -> Result<mailent_domain::RemediationRecord, StorageError> {
        let row: serde_json::Value = sqlx::query_scalar("INSERT INTO remediations(id, asset_id, investigation_id, finding_id, data) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id RETURNING data")
            .bind(record.id).bind(record.asset_id).bind(record.investigation_id).bind(record.finding.id).bind(serde_json::to_value(record).map_err(|e| StorageError::Backend(e.to_string()))?)
            .fetch_one(&*self.pool).await.map_err(|e| StorageError::Backend(e.to_string()))?;
        serde_json::from_value(row).map_err(|e| StorageError::Backend(e.to_string()))
    }
    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::RemediationRecord>, StorageError> {
        let row: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT data FROM remediations WHERE id=$1")
                .bind(id)
                .fetch_optional(&*self.pool)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        row.map(serde_json::from_value)
            .transpose()
            .map_err(|e| StorageError::Backend(e.to_string()))
    }
    async fn list_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Vec<mailent_domain::RemediationRecord>, StorageError> {
        let rows: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT data FROM remediations WHERE asset_id=$1 ORDER BY id")
                .bind(asset_id)
                .fetch_all(&*self.pool)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        rows.into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|e| StorageError::Backend(e.to_string()))
    }
    async fn list_verifying(&self) -> Result<Vec<mailent_domain::RemediationRecord>, StorageError> {
        let rows: Vec<serde_json::Value> =
            sqlx::query_scalar("SELECT data FROM remediations WHERE data->>'state' = 'verifying'")
                .fetch_all(&*self.pool)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        rows.into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|e| StorageError::Backend(e.to_string()))
    }
    async fn update(
        &self,
        record: &mailent_domain::RemediationRecord,
        expected_revision: i64,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE remediations SET data=$2 WHERE id=$1 AND (data->>'revision')::bigint=$3",
        )
        .bind(record.id)
        .bind(serde_json::to_value(record).map_err(|e| StorageError::Backend(e.to_string()))?)
        .bind(expected_revision)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }
}

#[async_trait]
impl PostureRepository for PostgresStorage {
    async fn save_snapshot(
        &self,
        snapshot: &mailent_domain::PostureSnapshot,
    ) -> Result<(), StorageError> {
        let worst_findings = serde_json::to_value(&snapshot.worst_findings)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let categories = serde_json::to_value(&snapshot.categories)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let deductions = serde_json::to_value(&snapshot.deductions)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let grade_str = snapshot.grade.to_string().to_lowercase();

        sqlx::query(
            r#"
            INSERT INTO posture_snapshots
            (id, asset_id, score, grade, score_capped, pre_cap_score, findings_considered,
             worst_findings, categories, deductions, change_reason, score_delta, recorded_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (id) DO UPDATE SET
                score = EXCLUDED.score,
                grade = EXCLUDED.grade,
                score_capped = EXCLUDED.score_capped,
                pre_cap_score = EXCLUDED.pre_cap_score,
                findings_considered = EXCLUDED.findings_considered,
                worst_findings = EXCLUDED.worst_findings,
                categories = EXCLUDED.categories,
                deductions = EXCLUDED.deductions,
                change_reason = EXCLUDED.change_reason,
                score_delta = EXCLUDED.score_delta,
                recorded_at = EXCLUDED.recorded_at
            "#,
        )
        .bind(snapshot.id)
        .bind(snapshot.asset_id)
        .bind(snapshot.score)
        .bind(grade_str)
        .bind(snapshot.score_capped)
        .bind(snapshot.pre_cap_score)
        .bind(snapshot.findings_considered as i32)
        .bind(worst_findings)
        .bind(categories)
        .bind(deductions)
        .bind(&snapshot.change_reason)
        .bind(snapshot.score_delta)
        .bind(snapshot.recorded_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save posture snapshot error: {e}")))?;

        Ok(())
    }

    async fn list_for_asset(
        &self,
        asset_id: Uuid,
        limit: usize,
    ) -> Result<Vec<mailent_domain::PostureSnapshot>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, asset_id, score, grade, score_capped, pre_cap_score, findings_considered,
                   worst_findings, categories, deductions, change_reason, score_delta, recorded_at
            FROM posture_snapshots
            WHERE asset_id = $1
            ORDER BY recorded_at DESC
            LIMIT $2
            "#,
        )
        .bind(asset_id)
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list posture snapshots error: {e}")))?;

        let mut snapshots = Vec::with_capacity(rows.len());
        for row in rows {
            let grade_str: String = row.get("grade");
            let score: f32 = row.get("score");
            let grade = match grade_str.as_str() {
                "strong" => mailent_domain::PostureGrade::Strong,
                "good" => mailent_domain::PostureGrade::Good,
                "moderate" => mailent_domain::PostureGrade::Moderate,
                "weak" => mailent_domain::PostureGrade::Weak,
                "critical" => mailent_domain::PostureGrade::Critical,
                _ => mailent_domain::PostureGrade::from_score(score),
            };
            let worst_val: serde_json::Value = row.get("worst_findings");
            let cat_val: serde_json::Value = row.get("categories");
            let ded_val: serde_json::Value = row.get("deductions");
            let worst_findings = serde_json::from_value(worst_val).unwrap_or_default();
            let categories = serde_json::from_value(cat_val).unwrap_or_default();
            let deductions = serde_json::from_value(ded_val).unwrap_or_default();

            snapshots.push(mailent_domain::PostureSnapshot {
                id: row.get("id"),
                asset_id: row.get("asset_id"),
                score,
                grade,
                score_capped: row.get("score_capped"),
                pre_cap_score: row.get("pre_cap_score"),
                findings_considered: row.get::<i32, _>("findings_considered") as usize,
                worst_findings,
                categories,
                deductions,
                change_reason: row.get("change_reason"),
                score_delta: row.get("score_delta"),
                recorded_at: row.get("recorded_at"),
            });
        }
        Ok(snapshots)
    }

    async fn latest_for_asset(
        &self,
        asset_id: Uuid,
    ) -> Result<Option<mailent_domain::PostureSnapshot>, StorageError> {
        let list = PostureRepository::list_for_asset(self, asset_id, 1).await?;
        Ok(list.into_iter().next())
    }
}

#[async_trait]
impl IntegrationRepository for PostgresStorage {
    async fn save(&self, config: &mailent_domain::IntegrationConfig) -> Result<(), StorageError> {
        let kind_str = match config.kind {
            mailent_domain::IntegrationKind::Webhook => "webhook",
            mailent_domain::IntegrationKind::Syslog => "syslog",
        };
        let event_types = serde_json::to_value(&config.event_types)
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO integrations
            (id, name, kind, destination, event_types, enabled, auth_header,
             last_delivery_at, last_status_code, last_error, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                kind = EXCLUDED.kind,
                destination = EXCLUDED.destination,
                event_types = EXCLUDED.event_types,
                enabled = EXCLUDED.enabled,
                auth_header = EXCLUDED.auth_header,
                last_delivery_at = EXCLUDED.last_delivery_at,
                last_status_code = EXCLUDED.last_status_code,
                last_error = EXCLUDED.last_error,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(config.id)
        .bind(&config.name)
        .bind(kind_str)
        .bind(&config.destination)
        .bind(event_types)
        .bind(config.enabled)
        .bind(&config.auth_header)
        .bind(config.last_delivery_at)
        .bind(config.last_status_code.map(|s| s as i32))
        .bind(&config.last_error)
        .bind(config.created_at)
        .bind(config.updated_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save integration error: {e}")))?;

        Ok(())
    }

    async fn list_all(&self) -> Result<Vec<mailent_domain::IntegrationConfig>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, kind, destination, event_types, enabled, auth_header,
                   last_delivery_at, last_status_code, last_error, created_at, updated_at
            FROM integrations
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list integrations error: {e}")))?;

        let mut configs = Vec::with_capacity(rows.len());
        for row in rows {
            let kind_str: String = row.get("kind");
            let kind = match kind_str.as_str() {
                "syslog" => mailent_domain::IntegrationKind::Syslog,
                _ => mailent_domain::IntegrationKind::Webhook,
            };
            let ev_val: serde_json::Value = row.get("event_types");
            let event_types = serde_json::from_value(ev_val).unwrap_or_default();
            let code: Option<i32> = row.get("last_status_code");

            configs.push(mailent_domain::IntegrationConfig {
                id: row.get("id"),
                name: row.get("name"),
                kind,
                destination: row.get("destination"),
                event_types,
                enabled: row.get("enabled"),
                auth_header: row.get("auth_header"),
                last_delivery_at: row.get("last_delivery_at"),
                last_status_code: code.map(|c| c as u16),
                last_error: row.get("last_error"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            });
        }
        Ok(configs)
    }

    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::IntegrationConfig>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, name, kind, destination, event_types, enabled, auth_header,
                   last_delivery_at, last_status_code, last_error, created_at, updated_at
            FROM integrations
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find integration error: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };
        let kind_str: String = row.get("kind");
        let kind = match kind_str.as_str() {
            "syslog" => mailent_domain::IntegrationKind::Syslog,
            _ => mailent_domain::IntegrationKind::Webhook,
        };
        let ev_val: serde_json::Value = row.get("event_types");
        let event_types = serde_json::from_value(ev_val).unwrap_or_default();
        let code: Option<i32> = row.get("last_status_code");

        Ok(Some(mailent_domain::IntegrationConfig {
            id: row.get("id"),
            name: row.get("name"),
            kind,
            destination: row.get("destination"),
            event_types,
            enabled: row.get("enabled"),
            auth_header: row.get("auth_header"),
            last_delivery_at: row.get("last_delivery_at"),
            last_status_code: code.map(|c| c as u16),
            last_error: row.get("last_error"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }))
    }

    async fn delete(&self, id: Uuid) -> Result<bool, StorageError> {
        let res = sqlx::query("DELETE FROM integrations WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(format!("delete integration error: {e}")))?;
        Ok(res.rows_affected() > 0)
    }

    async fn update_status(
        &self,
        id: Uuid,
        status_code: Option<u16>,
        error: Option<String>,
        at: time::OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            UPDATE integrations
            SET last_delivery_at = $2, last_status_code = $3, last_error = $4, updated_at = $2
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(at)
        .bind(status_code.map(|s| s as i32))
        .bind(error)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("update integration status error: {e}")))?;

        Ok(())
    }
}

#[async_trait]
impl ArchivedReportRepository for PostgresStorage {
    async fn archive(
        &self,
        report: &mailent_domain::ArchivedReportRecord,
    ) -> Result<(), StorageError> {
        let kind_str = match report.subject_kind {
            mailent_domain::PostureSubjectKind::Asset => "asset",
            mailent_domain::PostureSubjectKind::Session => "session",
            mailent_domain::PostureSubjectKind::Investigation => "investigation",
        };

        sqlx::query(
            r#"
            INSERT INTO archived_reports
            (id, report_id, subject_kind, subject_id, title, fingerprint,
             generated_at, archived_at, archived_by, notes, raw_json)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                notes = EXCLUDED.notes
            "#,
        )
        .bind(report.id)
        .bind(&report.report_id)
        .bind(kind_str)
        .bind(report.subject_id)
        .bind(&report.title)
        .bind(&report.fingerprint)
        .bind(report.generated_at)
        .bind(report.archived_at)
        .bind(&report.archived_by)
        .bind(&report.notes)
        .bind(&report.raw_report_json)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("archive report error: {e}")))?;

        Ok(())
    }

    async fn list_all(
        &self,
        limit: usize,
    ) -> Result<Vec<mailent_domain::ArchivedReportSummary>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, report_id, subject_kind, subject_id, title, fingerprint,
                   generated_at, archived_at, archived_by, notes
            FROM archived_reports
            ORDER BY archived_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list archived reports error: {e}")))?;

        let mut summaries = Vec::with_capacity(rows.len());
        for row in rows {
            let kind_str: String = row.get("subject_kind");
            let subject_kind = match kind_str.as_str() {
                "session" => mailent_domain::PostureSubjectKind::Session,
                "investigation" => mailent_domain::PostureSubjectKind::Investigation,
                _ => mailent_domain::PostureSubjectKind::Asset,
            };
            summaries.push(mailent_domain::ArchivedReportSummary {
                id: row.get("id"),
                report_id: row.get("report_id"),
                subject_kind,
                subject_id: row.get("subject_id"),
                title: row.get("title"),
                fingerprint: row.get("fingerprint"),
                generated_at: row.get("generated_at"),
                archived_at: row.get("archived_at"),
                archived_by: row.get("archived_by"),
                notes: row.get("notes"),
            });
        }
        Ok(summaries)
    }

    async fn list_for_subject(
        &self,
        subject_id: Uuid,
    ) -> Result<Vec<mailent_domain::ArchivedReportSummary>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, report_id, subject_kind, subject_id, title, fingerprint,
                   generated_at, archived_at, archived_by, notes
            FROM archived_reports
            WHERE subject_id = $1
            ORDER BY archived_at DESC
            "#,
        )
        .bind(subject_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list subject reports error: {e}")))?;

        let mut summaries = Vec::with_capacity(rows.len());
        for row in rows {
            let kind_str: String = row.get("subject_kind");
            let subject_kind = match kind_str.as_str() {
                "session" => mailent_domain::PostureSubjectKind::Session,
                "investigation" => mailent_domain::PostureSubjectKind::Investigation,
                _ => mailent_domain::PostureSubjectKind::Asset,
            };
            summaries.push(mailent_domain::ArchivedReportSummary {
                id: row.get("id"),
                report_id: row.get("report_id"),
                subject_kind,
                subject_id: row.get("subject_id"),
                title: row.get("title"),
                fingerprint: row.get("fingerprint"),
                generated_at: row.get("generated_at"),
                archived_at: row.get("archived_at"),
                archived_by: row.get("archived_by"),
                notes: row.get("notes"),
            });
        }
        Ok(summaries)
    }

    async fn find_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<mailent_domain::ArchivedReportRecord>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, report_id, subject_kind, subject_id, title, fingerprint,
                   generated_at, archived_at, archived_by, notes, raw_json
            FROM archived_reports
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find archived report error: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };
        let kind_str: String = row.get("subject_kind");
        let subject_kind = match kind_str.as_str() {
            "session" => mailent_domain::PostureSubjectKind::Session,
            "investigation" => mailent_domain::PostureSubjectKind::Investigation,
            _ => mailent_domain::PostureSubjectKind::Asset,
        };

        Ok(Some(mailent_domain::ArchivedReportRecord {
            id: row.get("id"),
            report_id: row.get("report_id"),
            subject_kind,
            subject_id: row.get("subject_id"),
            title: row.get("title"),
            fingerprint: row.get("fingerprint"),
            generated_at: row.get("generated_at"),
            archived_at: row.get("archived_at"),
            archived_by: row.get("archived_by"),
            notes: row.get("notes"),
            raw_report_json: row.get("raw_json"),
        }))
    }
}

#[async_trait]
impl AssessmentRepository for PostgresStorage {
    async fn save(&self, assessment: &AssessmentRecord) -> Result<(), StorageError> {
        let protocols_json = serde_json::to_value(&assessment.protocols_identified)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let protocol_evidence_json = serde_json::to_value(&assessment.protocol_evidence)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let session_ids_json = serde_json::to_value(&assessment.session_ids)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let asset_ids_json = serde_json::to_value(&assessment.asset_ids)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let finding_ids_json = serde_json::to_value(&assessment.finding_ids)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let evidence_gaps_json = serde_json::to_value(&assessment.evidence_gaps)
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let source_json = serde_json::to_value(&assessment.source)
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO assessments (
                id, title, capture_name, capture_hash, capture_size_bytes,
                created_at, time_range_start, time_range_end,
                protocols_identified, protocol_evidence, session_ids, asset_ids, finding_ids,
                posture_score, posture_grade, evidence_gaps,
                ai_risk_classification, ai_risk_rationale, ai_confidence, metadata, source, organization_id
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
            )
            ON CONFLICT (id) DO UPDATE SET
                title = EXCLUDED.title,
                source = EXCLUDED.source,
                protocols_identified = EXCLUDED.protocols_identified,
                protocol_evidence = EXCLUDED.protocol_evidence,
                session_ids = EXCLUDED.session_ids,
                asset_ids = EXCLUDED.asset_ids,
                finding_ids = EXCLUDED.finding_ids,
                posture_score = EXCLUDED.posture_score,
                posture_grade = EXCLUDED.posture_grade,
                evidence_gaps = EXCLUDED.evidence_gaps,
                ai_risk_classification = EXCLUDED.ai_risk_classification,
                ai_risk_rationale = EXCLUDED.ai_risk_rationale,
                ai_confidence = EXCLUDED.ai_confidence,
                metadata = EXCLUDED.metadata,
                organization_id = EXCLUDED.organization_id
            "#
        )
        .bind(assessment.id)
        .bind(&assessment.title)
        .bind(&assessment.capture_name)
        .bind(&assessment.capture_hash)
        .bind(assessment.capture_size_bytes as i64)
        .bind(assessment.created_at)
        .bind(assessment.time_range_start)
        .bind(assessment.time_range_end)
        .bind(protocols_json)
        .bind(protocol_evidence_json)
        .bind(session_ids_json)
        .bind(asset_ids_json)
        .bind(finding_ids_json)
        .bind(assessment.posture_score)
        .bind(&assessment.posture_grade)
        .bind(evidence_gaps_json)
        .bind(&assessment.ai_risk_classification)
        .bind(&assessment.ai_risk_rationale)
        .bind(assessment.ai_confidence)
        .bind(&assessment.metadata)
        .bind(source_json)
        .bind(assessment.organization_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save assessment error: {e}")))?;

        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<AssessmentRecord>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, title, capture_name, capture_hash, capture_size_bytes,
                   created_at, time_range_start, time_range_end,
                   protocols_identified, protocol_evidence, session_ids, asset_ids, finding_ids,
                   posture_score, posture_grade, evidence_gaps,
                   ai_risk_classification, ai_risk_rationale, ai_confidence, metadata, source, organization_id
            FROM assessments
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find assessment error: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        let protocols: serde_json::Value = row.get("protocols_identified");
        let protocol_evidence: serde_json::Value = row.get("protocol_evidence");
        let session_ids: serde_json::Value = row.get("session_ids");
        let asset_ids: serde_json::Value = row.get("asset_ids");
        let finding_ids: serde_json::Value = row.get("finding_ids");
        let evidence_gaps: serde_json::Value = row.get("evidence_gaps");
        let size_bytes: i64 = row.get("capture_size_bytes");
        let capture_name: String = row.get("capture_name");
        let capture_hash: String = row.get("capture_hash");
        let time_range_start: Option<OffsetDateTime> = row.get("time_range_start");
        let time_range_end: Option<OffsetDateTime> = row.get("time_range_end");

        let source: AssessmentSource = match row.try_get::<serde_json::Value, _>("source") {
            Ok(val) if !val.is_null() => serde_json::from_value(val).unwrap_or_else(|_| {
                AssessmentSource::Capture(CaptureMetadata {
                    capture_name: capture_name.clone(),
                    capture_hash: capture_hash.clone(),
                    capture_size_bytes: size_bytes as u64,
                    time_range_start,
                    time_range_end,
                })
            }),
            _ => AssessmentSource::Capture(CaptureMetadata {
                capture_name: capture_name.clone(),
                capture_hash: capture_hash.clone(),
                capture_size_bytes: size_bytes as u64,
                time_range_start,
                time_range_end,
            }),
        };

        Ok(Some(AssessmentRecord {
            id: row.get("id"),
            title: row.get("title"),
            source,
            capture_name,
            capture_hash,
            capture_size_bytes: size_bytes as u64,
            created_at: row.get("created_at"),
            time_range_start,
            time_range_end,
            protocols_identified: serde_json::from_value(protocols).unwrap_or_default(),
            protocol_evidence: serde_json::from_value(protocol_evidence).unwrap_or_default(),
            session_ids: serde_json::from_value(session_ids).unwrap_or_default(),
            asset_ids: serde_json::from_value(asset_ids).unwrap_or_default(),
            finding_ids: serde_json::from_value(finding_ids).unwrap_or_default(),
            posture_score: row.get("posture_score"),
            posture_grade: row.get("posture_grade"),
            evidence_gaps: serde_json::from_value(evidence_gaps).unwrap_or_default(),
            ai_risk_classification: row.get("ai_risk_classification"),
            ai_risk_rationale: row.get("ai_risk_rationale"),
            ai_confidence: row.get("ai_confidence"),
            metadata: row.get("metadata"),
            organization_id: row.get("organization_id"),
        }))
    }

    async fn find_by_id_scoped(
        &self,
        id: Uuid,
        organization_id: Uuid,
    ) -> Result<Option<AssessmentRecord>, StorageError> {
        let assessment = AssessmentRepository::find_by_id(self, id).await?;
        match assessment {
            Some(a) if a.organization_id == Some(organization_id) => Ok(Some(a)),
            _ => Ok(None),
        }
    }

    async fn list_all(&self) -> Result<Vec<AssessmentSummary>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, title, capture_name, capture_hash, capture_size_bytes,
                   created_at, protocols_identified, session_ids, finding_ids,
                   posture_score, posture_grade, ai_risk_classification, source, organization_id
            FROM assessments
            ORDER BY created_at DESC
            "#,
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list assessments error: {e}")))?;

        let mut list = Vec::new();
        for row in rows {
            let protocols: serde_json::Value = row.get("protocols_identified");
            let session_ids: serde_json::Value = row.get("session_ids");
            let finding_ids: serde_json::Value = row.get("finding_ids");
            let size_bytes: i64 = row.get("capture_size_bytes");
            let capture_name: String = row.get("capture_name");

            let s_ids: Vec<Uuid> = serde_json::from_value(session_ids).unwrap_or_default();
            let f_ids: Vec<Uuid> = serde_json::from_value(finding_ids).unwrap_or_default();

            let (source_type, target) = match row.try_get::<serde_json::Value, _>("source") {
                Ok(val) if !val.is_null() => {
                    match serde_json::from_value::<AssessmentSource>(val) {
                        Ok(AssessmentSource::Capture(c)) => ("capture".to_string(), c.capture_name),
                        Ok(AssessmentSource::Infrastructure(i)) => {
                            ("infrastructure".to_string(), i.target_domain)
                        }
                        Err(_) => ("capture".to_string(), capture_name.clone()),
                    }
                }
                _ => ("capture".to_string(), capture_name.clone()),
            };

            list.push(AssessmentSummary {
                id: row.get("id"),
                title: row.get("title"),
                source_type,
                target,
                capture_name,
                capture_hash: row.get("capture_hash"),
                capture_size_bytes: size_bytes as u64,
                created_at: row.get("created_at"),
                protocols_identified: serde_json::from_value(protocols).unwrap_or_default(),
                session_count: s_ids.len(),
                finding_count: f_ids.len(),
                posture_score: row.get("posture_score"),
                posture_grade: row.get("posture_grade"),
                ai_risk_classification: row.get("ai_risk_classification"),
                organization_id: row.get("organization_id"),
            });
        }
        Ok(list)
    }

    async fn list_for_org(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<AssessmentSummary>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, title, capture_name, capture_hash, capture_size_bytes,
                   created_at, protocols_identified, session_ids, finding_ids,
                   posture_score, posture_grade, ai_risk_classification, source, organization_id
            FROM assessments
            WHERE organization_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(organization_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list assessments for org error: {e}")))?;

        let mut list = Vec::new();
        for row in rows {
            let protocols: serde_json::Value = row.get("protocols_identified");
            let session_ids: serde_json::Value = row.get("session_ids");
            let finding_ids: serde_json::Value = row.get("finding_ids");
            let size_bytes: i64 = row.get("capture_size_bytes");
            let capture_name: String = row.get("capture_name");

            let s_ids: Vec<Uuid> = serde_json::from_value(session_ids).unwrap_or_default();
            let f_ids: Vec<Uuid> = serde_json::from_value(finding_ids).unwrap_or_default();

            let (source_type, target) = match row.try_get::<serde_json::Value, _>("source") {
                Ok(val) if !val.is_null() => {
                    match serde_json::from_value::<AssessmentSource>(val) {
                        Ok(AssessmentSource::Capture(c)) => ("capture".to_string(), c.capture_name),
                        Ok(AssessmentSource::Infrastructure(i)) => {
                            ("infrastructure".to_string(), i.target_domain)
                        }
                        Err(_) => ("capture".to_string(), capture_name.clone()),
                    }
                }
                _ => ("capture".to_string(), capture_name.clone()),
            };

            list.push(AssessmentSummary {
                id: row.get("id"),
                title: row.get("title"),
                source_type,
                target,
                capture_name,
                capture_hash: row.get("capture_hash"),
                capture_size_bytes: size_bytes as u64,
                created_at: row.get("created_at"),
                protocols_identified: serde_json::from_value(protocols).unwrap_or_default(),
                session_count: s_ids.len(),
                finding_count: f_ids.len(),
                posture_score: row.get("posture_score"),
                posture_grade: row.get("posture_grade"),
                ai_risk_classification: row.get("ai_risk_classification"),
                organization_id: row.get("organization_id"),
            });
        }
        Ok(list)
    }
}

#[async_trait]
impl OrganizationRepository for PostgresStorage {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>, StorageError> {
        let row = sqlx::query("SELECT id, name, slug, created_at FROM organizations WHERE id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(format!("find organization by id error: {e}")))?;

        Ok(row.map(|r| Organization {
            id: r.get("id"),
            name: r.get("name"),
            slug: r.get("slug"),
            created_at: r.get("created_at"),
        }))
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>, StorageError> {
        let row =
            sqlx::query("SELECT id, name, slug, created_at FROM organizations WHERE slug = $1")
                .bind(slug)
                .fetch_optional(&*self.pool)
                .await
                .map_err(|e| {
                    StorageError::Backend(format!("find organization by slug error: {e}"))
                })?;

        Ok(row.map(|r| Organization {
            id: r.get("id"),
            name: r.get("name"),
            slug: r.get("slug"),
            created_at: r.get("created_at"),
        }))
    }

    async fn list_for_user(&self, user_id: &str) -> Result<Vec<Organization>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT o.id, o.name, o.slug, o.created_at
            FROM organizations o
            JOIN organization_members om ON om.organization_id = o.id
            WHERE om.user_id = $1
            ORDER BY o.created_at ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list organizations for user error: {e}")))?;

        let mut list: Vec<Organization> = rows
            .into_iter()
            .map(|r| Organization {
                id: r.get("id"),
                name: r.get("name"),
                slug: r.get("slug"),
                created_at: r.get("created_at"),
            })
            .collect();

        if list.is_empty()
            && let Some(default_org) =
                OrganizationRepository::find_by_id(self, mailent_domain::DEFAULT_ORG_ID).await?
        {
            list.push(default_org);
        }

        Ok(list)
    }

    async fn save(&self, org: &Organization) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO organizations (id, name, slug, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, slug = EXCLUDED.slug
            "#,
        )
        .bind(org.id)
        .bind(&org.name)
        .bind(&org.slug)
        .bind(org.created_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save organization error: {e}")))?;

        Ok(())
    }

    async fn add_member(&self, member: &OrganizationMember) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO organization_members (organization_id, user_id, role, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role
            "#,
        )
        .bind(member.organization_id)
        .bind(&member.user_id)
        .bind(&member.role)
        .bind(member.created_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("add organization member error: {e}")))?;

        Ok(())
    }

    async fn get_member(
        &self,
        organization_id: Uuid,
        user_id: &str,
    ) -> Result<Option<OrganizationMember>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT organization_id, user_id, role, created_at
            FROM organization_members
            WHERE organization_id = $1 AND user_id = $2
            "#,
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("get organization member error: {e}")))?;

        Ok(row.map(|r| OrganizationMember {
            organization_id: r.get("organization_id"),
            user_id: r.get("user_id"),
            role: r.get("role"),
            created_at: r.get("created_at"),
        }))
    }
}

#[async_trait]
impl DeviceRepository for PostgresStorage {
    async fn save_device(&self, device: &Device) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO devices (
                id, organization_id, registered_by_user_id, name,
                hostname, platform, architecture, created_at,
                last_seen_at, revoked_at, capabilities,
                version, agent_enabled, agent_status, current_job_id, completed_jobs_count
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
            )
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                hostname = EXCLUDED.hostname,
                platform = EXCLUDED.platform,
                architecture = EXCLUDED.architecture,
                last_seen_at = EXCLUDED.last_seen_at,
                revoked_at = EXCLUDED.revoked_at,
                capabilities = EXCLUDED.capabilities,
                version = EXCLUDED.version,
                agent_enabled = EXCLUDED.agent_enabled,
                agent_status = EXCLUDED.agent_status,
                current_job_id = EXCLUDED.current_job_id,
                completed_jobs_count = EXCLUDED.completed_jobs_count
            "#,
        )
        .bind(device.id)
        .bind(device.organization_id)
        .bind(&device.registered_by_user_id)
        .bind(&device.name)
        .bind(&device.hostname)
        .bind(&device.platform)
        .bind(&device.architecture)
        .bind(device.created_at)
        .bind(device.last_seen_at)
        .bind(device.revoked_at)
        .bind(&device.capabilities)
        .bind(&device.version)
        .bind(device.agent_enabled)
        .bind(&device.agent_status)
        .bind(device.current_job_id)
        .bind(device.completed_jobs_count as i32)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save device error: {e}")))?;

        Ok(())
    }

    async fn find_device_by_id(&self, id: Uuid) -> Result<Option<Device>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, organization_id, registered_by_user_id, name,
                   hostname, platform, architecture, created_at,
                   last_seen_at, revoked_at, capabilities,
                   version, agent_enabled, agent_status, current_job_id, completed_jobs_count
            FROM devices
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find device error: {e}")))?;

        Ok(row.map(|r| Device {
            id: r.get("id"),
            organization_id: r.get("organization_id"),
            registered_by_user_id: r.get("registered_by_user_id"),
            name: r.get("name"),
            hostname: r.get("hostname"),
            platform: r.get("platform"),
            architecture: r.get("architecture"),
            created_at: r.get("created_at"),
            last_seen_at: r.get("last_seen_at"),
            revoked_at: r.get("revoked_at"),
            capabilities: r.get("capabilities"),
            version: r.try_get("version").ok(),
            agent_enabled: r.try_get("agent_enabled").unwrap_or(false),
            agent_status: r.try_get("agent_status").ok(),
            current_job_id: r.try_get("current_job_id").ok(),
            completed_jobs_count: r
                .try_get::<i32, _>("completed_jobs_count")
                .map(|c| c as u32)
                .unwrap_or(0),
        }))
    }

    async fn list_devices_for_org(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<Device>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, organization_id, registered_by_user_id, name,
                   hostname, platform, architecture, created_at,
                   last_seen_at, revoked_at, capabilities,
                   version, agent_enabled, agent_status, current_job_id, completed_jobs_count
            FROM devices
            WHERE organization_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(organization_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list devices error: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| Device {
                id: r.get("id"),
                organization_id: r.get("organization_id"),
                registered_by_user_id: r.get("registered_by_user_id"),
                name: r.get("name"),
                hostname: r.get("hostname"),
                platform: r.get("platform"),
                architecture: r.get("architecture"),
                created_at: r.get("created_at"),
                last_seen_at: r.get("last_seen_at"),
                revoked_at: r.get("revoked_at"),
                capabilities: r.get("capabilities"),
                version: r.try_get("version").ok(),
                agent_enabled: r.try_get("agent_enabled").unwrap_or(false),
                agent_status: r.try_get("agent_status").ok(),
                current_job_id: r.try_get("current_job_id").ok(),
                completed_jobs_count: r
                    .try_get::<i32, _>("completed_jobs_count")
                    .map(|c| c as u32)
                    .unwrap_or(0),
            })
            .collect())
    }

    async fn revoke_device(&self, id: Uuid) -> Result<(), StorageError> {
        sqlx::query("UPDATE devices SET revoked_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(format!("revoke device error: {e}")))?;
        Ok(())
    }

    async fn create_challenge(
        &self,
        challenge: &DeviceAuthorizationChallenge,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO device_challenges (
                code, device_name, hostname, platform, architecture,
                expires_at, authorized_at, authorized_by_user_id,
                organization_id, issued_token, device_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (code) DO UPDATE SET
                device_name = EXCLUDED.device_name,
                hostname = EXCLUDED.hostname,
                platform = EXCLUDED.platform,
                architecture = EXCLUDED.architecture,
                expires_at = EXCLUDED.expires_at,
                authorized_at = EXCLUDED.authorized_at,
                authorized_by_user_id = EXCLUDED.authorized_by_user_id,
                organization_id = EXCLUDED.organization_id,
                issued_token = EXCLUDED.issued_token,
                device_id = EXCLUDED.device_id
            "#,
        )
        .bind(&challenge.code)
        .bind(&challenge.device_name)
        .bind(&challenge.hostname)
        .bind(&challenge.platform)
        .bind(&challenge.architecture)
        .bind(challenge.expires_at)
        .bind(challenge.authorized_at)
        .bind(&challenge.authorized_by_user_id)
        .bind(challenge.organization_id)
        .bind(&challenge.issued_token)
        .bind(challenge.device_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("create challenge error: {e}")))?;
        Ok(())
    }

    async fn get_challenge(
        &self,
        code: &str,
    ) -> Result<Option<DeviceAuthorizationChallenge>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT code, device_name, hostname, platform, architecture,
                   expires_at, authorized_at, authorized_by_user_id,
                   organization_id, issued_token, device_id
            FROM device_challenges
            WHERE code = $1
            "#,
        )
        .bind(code)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("get challenge error: {e}")))?;

        Ok(row.map(|r| DeviceAuthorizationChallenge {
            code: r.get("code"),
            device_name: r.get("device_name"),
            hostname: r.get("hostname"),
            platform: r.get("platform"),
            architecture: r.get("architecture"),
            expires_at: r.get("expires_at"),
            authorized_at: r.get("authorized_at"),
            authorized_by_user_id: r.get("authorized_by_user_id"),
            organization_id: r.get("organization_id"),
            issued_token: r.get("issued_token"),
            device_id: r.get("device_id"),
        }))
    }

    async fn approve_challenge(
        &self,
        code: &str,
        user_id: &str,
        org_id: Uuid,
        device_token: &str,
        device_id: Uuid,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            UPDATE device_challenges
            SET authorized_at = NOW(),
                authorized_by_user_id = $2,
                organization_id = $3,
                issued_token = $4,
                device_id = $5
            WHERE code = $1
            "#,
        )
        .bind(code)
        .bind(user_id)
        .bind(org_id)
        .bind(device_token)
        .bind(device_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("approve challenge error: {e}")))?;
        Ok(())
    }

    async fn save_device_token(
        &self,
        token_hash: &str,
        device_id: Uuid,
        org_id: Uuid,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO device_tokens (token_hash, device_id, organization_id, created_at, last_used_at)
            VALUES ($1, $2, $3, NOW(), NOW())
            ON CONFLICT (token_hash) DO UPDATE SET last_used_at = NOW()
            "#,
        )
        .bind(token_hash)
        .bind(device_id)
        .bind(org_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save device token error: {e}")))?;
        Ok(())
    }

    async fn validate_device_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<(Device, Uuid)>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT d.id, d.organization_id, d.registered_by_user_id, d.name,
                   d.hostname, d.platform, d.architecture, d.created_at,
                   d.last_seen_at, d.revoked_at, d.capabilities,
                   d.version, d.agent_enabled, d.agent_status, d.current_job_id, d.completed_jobs_count,
                   dt.organization_id as token_org_id
            FROM device_tokens dt
            JOIN devices d ON d.id = dt.device_id
            WHERE dt.token_hash = $1 AND d.revoked_at IS NULL
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("validate device token error: {e}")))?;

        if let Some(r) = row {
            let device_id: Uuid = r.get("id");
            let _ =
                sqlx::query("UPDATE device_tokens SET last_used_at = NOW() WHERE token_hash = $1")
                    .bind(token_hash)
                    .execute(&*self.pool)
                    .await;
            let _ = sqlx::query("UPDATE devices SET last_seen_at = NOW() WHERE id = $1")
                .bind(device_id)
                .execute(&*self.pool)
                .await;
            let token_org_id: Uuid = r.get("token_org_id");
            Ok(Some((
                Device {
                    id: device_id,
                    organization_id: r.get("organization_id"),
                    registered_by_user_id: r.get("registered_by_user_id"),
                    name: r.get("name"),
                    hostname: r.get("hostname"),
                    platform: r.get("platform"),
                    architecture: r.get("architecture"),
                    created_at: r.get("created_at"),
                    last_seen_at: r.get("last_seen_at"),
                    revoked_at: r.get("revoked_at"),
                    capabilities: r.get("capabilities"),
                    version: r.try_get("version").ok(),
                    agent_enabled: r.try_get("agent_enabled").unwrap_or(false),
                    agent_status: r.try_get("agent_status").ok(),
                    current_job_id: r.try_get("current_job_id").ok(),
                    completed_jobs_count: r
                        .try_get::<i32, _>("completed_jobs_count")
                        .map(|c| c as u32)
                        .unwrap_or(0),
                },
                token_org_id,
            )))
        } else {
            Ok(None)
        }
    }

    async fn revoke_device_token(&self, token_hash: &str) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            UPDATE devices SET revoked_at = NOW()
            WHERE id IN (SELECT device_id FROM device_tokens WHERE token_hash = $1)
            "#,
        )
        .bind(token_hash)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("revoke device token error: {e}")))?;

        sqlx::query("DELETE FROM device_tokens WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&*self.pool)
            .await
            .map_err(|e| StorageError::Backend(format!("delete device token error: {e}")))?;

        Ok(())
    }

    async fn heartbeat(
        &self,
        device_id: Uuid,
        version: Option<String>,
        capabilities: Vec<String>,
        status: String,
        now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            UPDATE devices
            SET last_seen_at = $2,
                version = COALESCE($3, version),
                capabilities = CASE WHEN array_length($4::text[], 1) > 0 THEN $4 ELSE capabilities END,
                agent_enabled = true,
                agent_status = $5
            WHERE id = $1 AND revoked_at IS NULL
            "#,
        )
        .bind(device_id)
        .bind(now)
        .bind(version)
        .bind(&capabilities)
        .bind(status)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("device heartbeat error: {e}")))?;
        Ok(())
    }

    async fn update_agent_status(
        &self,
        device_id: Uuid,
        status: Option<String>,
        current_job_id: Option<Uuid>,
        increment_completed: bool,
    ) -> Result<(), StorageError> {
        let inc = if increment_completed { 1 } else { 0 };
        sqlx::query(
            r#"
            UPDATE devices
            SET agent_status = COALESCE($2, agent_status),
                current_job_id = $3,
                completed_jobs_count = completed_jobs_count + $4
            WHERE id = $1
            "#,
        )
        .bind(device_id)
        .bind(status)
        .bind(current_job_id)
        .bind(inc)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("update agent status error: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl JobRepository for PostgresStorage {
    async fn create_job(&self, job: &AgentJob) -> Result<(), StorageError> {
        let exec_target = serde_json::to_value(&job.execution_target)
            .map_err(|e| StorageError::Backend(format!("Serialization error: {e}")))?;
        let job_type = serde_json::to_value(&job.job_type)
            .map_err(|e| StorageError::Backend(format!("Serialization error: {e}")))?;
        let state_str = match job.state {
            JobState::Pending => "pending",
            JobState::Leased => "leased",
            JobState::Running => "running",
            JobState::Completed => "completed",
            JobState::Failed => "failed",
            JobState::Canceled => "canceled",
        };

        sqlx::query(
            r#"
            INSERT INTO agent_jobs (
                id, organization_id, target_agent_id, execution_target,
                job_type, state, created_at, available_at,
                leased_at, lease_expires_at, started_at, completed_at,
                attempt, max_attempts, result_assessment_id,
                last_error, idempotency_key, monitor_id
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
            )
            ON CONFLICT (id) DO UPDATE SET
                state = EXCLUDED.state,
                leased_at = EXCLUDED.leased_at,
                lease_expires_at = EXCLUDED.lease_expires_at,
                started_at = EXCLUDED.started_at,
                completed_at = EXCLUDED.completed_at,
                attempt = EXCLUDED.attempt,
                result_assessment_id = EXCLUDED.result_assessment_id,
                last_error = EXCLUDED.last_error
            "#,
        )
        .bind(job.id)
        .bind(job.organization_id)
        .bind(job.target_agent_id)
        .bind(exec_target)
        .bind(job_type)
        .bind(state_str)
        .bind(job.created_at)
        .bind(job.available_at)
        .bind(job.leased_at)
        .bind(job.lease_expires_at)
        .bind(job.started_at)
        .bind(job.completed_at)
        .bind(job.attempt as i32)
        .bind(job.max_attempts as i32)
        .bind(job.result_assessment_id)
        .bind(&job.last_error)
        .bind(&job.idempotency_key)
        .bind(job.monitor_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("create job error: {e}")))?;

        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<AgentJob>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, organization_id, target_agent_id, execution_target,
                   job_type, state, created_at, available_at,
                   leased_at, lease_expires_at, started_at, completed_at,
                   attempt, max_attempts, result_assessment_id,
                   last_error, idempotency_key, monitor_id
            FROM agent_jobs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find job error: {e}")))?;

        match row {
            Some(r) => Ok(Some(map_job_row(r)?)),
            None => Ok(None),
        }
    }

    async fn find_by_idempotency_key(
        &self,
        org_id: Uuid,
        key: &str,
    ) -> Result<Option<AgentJob>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, organization_id, target_agent_id, execution_target,
                   job_type, state, created_at, available_at,
                   leased_at, lease_expires_at, started_at, completed_at,
                   attempt, max_attempts, result_assessment_id,
                   last_error, idempotency_key, monitor_id
            FROM agent_jobs
            WHERE organization_id = $1 AND idempotency_key = $2
            "#,
        )
        .bind(org_id)
        .bind(key)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find job by idempotency error: {e}")))?;

        match row {
            Some(r) => Ok(Some(map_job_row(r)?)),
            None => Ok(None),
        }
    }

    async fn lease_next_job(
        &self,
        agent_id: Uuid,
        org_id: Uuid,
        now: OffsetDateTime,
        lease_duration_secs: u64,
    ) -> Result<Option<AgentJob>, StorageError> {
        let lease_expires = now + time::Duration::seconds(lease_duration_secs as i64);

        let row = sqlx::query(
            r#"
            UPDATE agent_jobs
            SET state = 'leased',
                leased_at = $3,
                lease_expires_at = $4,
                attempt = attempt + 1
            WHERE id = (
                SELECT id
                FROM agent_jobs
                WHERE organization_id = $2
                  AND (state = 'pending' OR (state IN ('leased', 'running') AND lease_expires_at < $3))
                  AND (target_agent_id = $1 OR (target_agent_id IS NULL AND execution_target->>'type' = 'agent'))
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING id, organization_id, target_agent_id, execution_target,
                      job_type, state, created_at, available_at,
                      leased_at, lease_expires_at, started_at, completed_at,
                      attempt, max_attempts, result_assessment_id,
                      last_error, idempotency_key, monitor_id
            "#,
        )
        .bind(agent_id)
        .bind(org_id)
        .bind(now)
        .bind(lease_expires)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("lease next job error: {e}")))?;

        match row {
            Some(r) => Ok(Some(map_job_row(r)?)),
            None => Ok(None),
        }
    }

    async fn lease_next_cloud_job(
        &self,
        now: OffsetDateTime,
        lease_duration_secs: u64,
    ) -> Result<Option<AgentJob>, StorageError> {
        let lease_expires = now + time::Duration::seconds(lease_duration_secs as i64);

        let row = sqlx::query(
            r#"
            UPDATE agent_jobs
            SET state = 'leased',
                leased_at = $1,
                lease_expires_at = $2,
                attempt = attempt + 1
            WHERE id = (
                SELECT id
                FROM agent_jobs
                WHERE (execution_target->>'type' = 'cloud' OR target_agent_id IS NULL)
                  AND (state = 'pending' OR (state IN ('leased', 'running') AND lease_expires_at < $1))
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING id, organization_id, target_agent_id, execution_target,
                      job_type, state, created_at, available_at,
                      leased_at, lease_expires_at, started_at, completed_at,
                      attempt, max_attempts, result_assessment_id,
                      last_error, idempotency_key, monitor_id
            "#,
        )
        .bind(now)
        .bind(lease_expires)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("lease cloud job error: {e}")))?;

        match row {
            Some(r) => Ok(Some(map_job_row(r)?)),
            None => Ok(None),
        }
    }

    async fn update_job(&self, job: &AgentJob) -> Result<(), StorageError> {
        self.create_job(job).await
    }

    async fn recover_expired_leases(&self, now: OffsetDateTime) -> Result<u64, StorageError> {
        let res = sqlx::query(
            r#"
            UPDATE agent_jobs
            SET state = CASE WHEN attempt >= max_attempts THEN 'failed' ELSE 'pending' END,
                leased_at = NULL,
                lease_expires_at = NULL,
                last_error = CASE WHEN attempt >= max_attempts THEN 'Max lease attempts exceeded' ELSE last_error END
            WHERE state IN ('leased', 'running') AND lease_expires_at < $1
            "#,
        )
        .bind(now)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("recover expired leases error: {e}")))?;

        Ok(res.rows_affected())
    }

    async fn list_for_org(
        &self,
        org_id: Uuid,
        limit: usize,
    ) -> Result<Vec<AgentJob>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, organization_id, target_agent_id, execution_target,
                   job_type, state, created_at, available_at,
                   leased_at, lease_expires_at, started_at, completed_at,
                   attempt, max_attempts, result_assessment_id,
                   last_error, idempotency_key, monitor_id
            FROM agent_jobs
            WHERE organization_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(org_id)
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list jobs error: {e}")))?;

        let mut jobs = Vec::with_capacity(rows.len());
        for r in rows {
            jobs.push(map_job_row(r)?);
        }
        Ok(jobs)
    }

    async fn count_active_for_org(&self, org_id: Uuid) -> Result<usize, StorageError> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM agent_jobs
            WHERE organization_id = $1 AND state IN ('pending', 'leased', 'running')
            "#,
        )
        .bind(org_id)
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("count jobs for org error: {e}")))?;

        Ok(count.0 as usize)
    }

    async fn count_active_for_agent(&self, agent_id: Uuid) -> Result<usize, StorageError> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM agent_jobs
            WHERE target_agent_id = $1 AND state IN ('leased', 'running')
            "#,
        )
        .bind(agent_id)
        .fetch_one(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("count jobs for agent error: {e}")))?;

        Ok(count.0 as usize)
    }
}

#[async_trait]
impl MonitorRepository for PostgresStorage {
    async fn save(&self, monitor: &InfrastructureMonitor) -> Result<(), StorageError> {
        let exec_target = serde_json::to_value(&monitor.execution_target)
            .map_err(|e| StorageError::Backend(format!("Serialization error: {e}")))?;
        let cadence_str = match monitor.cadence {
            MonitorCadence::Hourly => "hourly",
            MonitorCadence::Every6Hours => "every_6_hours",
            MonitorCadence::Every12Hours => "every_12_hours",
            MonitorCadence::Daily => "daily",
            MonitorCadence::Weekly => "weekly",
        };

        sqlx::query(
            r#"
            INSERT INTO infrastructure_monitors (
                id, organization_id, domain, enabled, execution_target,
                cadence, next_run_at, last_run_at, last_success_at,
                last_failure_at, last_assessment_id, last_error,
                created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
            )
            ON CONFLICT (organization_id, domain) DO UPDATE SET
                enabled = EXCLUDED.enabled,
                execution_target = EXCLUDED.execution_target,
                cadence = EXCLUDED.cadence,
                next_run_at = EXCLUDED.next_run_at,
                last_run_at = EXCLUDED.last_run_at,
                last_success_at = EXCLUDED.last_success_at,
                last_failure_at = EXCLUDED.last_failure_at,
                last_assessment_id = EXCLUDED.last_assessment_id,
                last_error = EXCLUDED.last_error,
                updated_at = EXCLUDED.updated_at
            "#,
        )
        .bind(monitor.id)
        .bind(monitor.organization_id)
        .bind(&monitor.domain)
        .bind(monitor.enabled)
        .bind(exec_target)
        .bind(cadence_str)
        .bind(monitor.next_run_at)
        .bind(monitor.last_run_at)
        .bind(monitor.last_success_at)
        .bind(monitor.last_failure_at)
        .bind(monitor.last_assessment_id)
        .bind(&monitor.last_error)
        .bind(monitor.created_at)
        .bind(monitor.updated_at)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("save monitor error: {e}")))?;

        Ok(())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<InfrastructureMonitor>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, organization_id, domain, enabled, execution_target,
                   cadence, next_run_at, last_run_at, last_success_at,
                   last_failure_at, last_assessment_id, last_error,
                   created_at, updated_at
            FROM infrastructure_monitors
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find monitor error: {e}")))?;

        match row {
            Some(r) => Ok(Some(map_monitor_row(r)?)),
            None => Ok(None),
        }
    }

    async fn find_by_domain(
        &self,
        org_id: Uuid,
        domain: &str,
    ) -> Result<Option<InfrastructureMonitor>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT id, organization_id, domain, enabled, execution_target,
                   cadence, next_run_at, last_run_at, last_success_at,
                   last_failure_at, last_assessment_id, last_error,
                   created_at, updated_at
            FROM infrastructure_monitors
            WHERE organization_id = $1 AND LOWER(domain) = LOWER($2)
            "#,
        )
        .bind(org_id)
        .bind(domain)
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find monitor by domain error: {e}")))?;

        match row {
            Some(r) => Ok(Some(map_monitor_row(r)?)),
            None => Ok(None),
        }
    }

    async fn list_for_org(&self, org_id: Uuid) -> Result<Vec<InfrastructureMonitor>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, organization_id, domain, enabled, execution_target,
                   cadence, next_run_at, last_run_at, last_success_at,
                   last_failure_at, last_assessment_id, last_error,
                   created_at, updated_at
            FROM infrastructure_monitors
            WHERE organization_id = $1
            ORDER BY domain ASC
            "#,
        )
        .bind(org_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("list monitors error: {e}")))?;

        let mut list = Vec::with_capacity(rows.len());
        for r in rows {
            list.push(map_monitor_row(r)?);
        }
        Ok(list)
    }

    async fn find_due_monitors(
        &self,
        now: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<InfrastructureMonitor>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT id, organization_id, domain, enabled, execution_target,
                   cadence, next_run_at, last_run_at, last_success_at,
                   last_failure_at, last_assessment_id, last_error,
                   created_at, updated_at
            FROM infrastructure_monitors
            WHERE enabled = true AND next_run_at <= $1
            ORDER BY next_run_at ASC
            LIMIT $2
            "#,
        )
        .bind(now)
        .bind(limit as i64)
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("find due monitors error: {e}")))?;

        let mut list = Vec::with_capacity(rows.len());
        for r in rows {
            list.push(map_monitor_row(r)?);
        }
        Ok(list)
    }

    async fn delete(&self, id: Uuid, org_id: Uuid) -> Result<bool, StorageError> {
        let res = sqlx::query(
            "DELETE FROM infrastructure_monitors WHERE id = $1 AND organization_id = $2",
        )
        .bind(id)
        .bind(org_id)
        .execute(&*self.pool)
        .await
        .map_err(|e| StorageError::Backend(format!("delete monitor error: {e}")))?;

        Ok(res.rows_affected() > 0)
    }
}

fn map_job_row(r: sqlx::postgres::PgRow) -> Result<AgentJob, StorageError> {
    let exec_target_val: serde_json::Value = r.get("execution_target");
    let execution_target: JobExecutionTarget = serde_json::from_value(exec_target_val)
        .map_err(|e| StorageError::Backend(format!("Serialization error: {e}")))?;

    let job_type_val: serde_json::Value = r.get("job_type");
    let job_type: AgentJobType = serde_json::from_value(job_type_val)
        .map_err(|e| StorageError::Backend(format!("Serialization error: {e}")))?;

    let state_str: String = r.get("state");
    let state = match state_str.as_str() {
        "pending" => JobState::Pending,
        "leased" => JobState::Leased,
        "running" => JobState::Running,
        "completed" => JobState::Completed,
        "failed" => JobState::Failed,
        "canceled" => JobState::Canceled,
        _ => JobState::Pending,
    };

    let attempt: i32 = r.get("attempt");
    let max_attempts: i32 = r.get("max_attempts");

    Ok(AgentJob {
        id: r.get("id"),
        organization_id: r.get("organization_id"),
        target_agent_id: r.get("target_agent_id"),
        execution_target,
        job_type,
        state,
        created_at: r.get("created_at"),
        available_at: r.get("available_at"),
        leased_at: r.get("leased_at"),
        lease_expires_at: r.get("lease_expires_at"),
        started_at: r.get("started_at"),
        completed_at: r.get("completed_at"),
        attempt: attempt as u32,
        max_attempts: max_attempts as u32,
        result_assessment_id: r.get("result_assessment_id"),
        last_error: r.get("last_error"),
        idempotency_key: r.get("idempotency_key"),
        monitor_id: r.get("monitor_id"),
    })
}

fn map_monitor_row(r: sqlx::postgres::PgRow) -> Result<InfrastructureMonitor, StorageError> {
    let exec_target_val: serde_json::Value = r.get("execution_target");
    let execution_target: MonitorExecutionTarget = serde_json::from_value(exec_target_val)
        .map_err(|e| StorageError::Backend(format!("Serialization error: {e}")))?;

    let cadence_str: String = r.get("cadence");
    let cadence = match cadence_str.as_str() {
        "hourly" => MonitorCadence::Hourly,
        "every_6_hours" => MonitorCadence::Every6Hours,
        "every_12_hours" => MonitorCadence::Every12Hours,
        "daily" => MonitorCadence::Daily,
        "weekly" => MonitorCadence::Weekly,
        _ => MonitorCadence::Daily,
    };

    Ok(InfrastructureMonitor {
        id: r.get("id"),
        organization_id: r.get("organization_id"),
        domain: r.get("domain"),
        enabled: r.get("enabled"),
        execution_target,
        cadence,
        next_run_at: r.get("next_run_at"),
        last_run_at: r.get("last_run_at"),
        last_success_at: r.get("last_success_at"),
        last_failure_at: r.get("last_failure_at"),
        last_assessment_id: r.get("last_assessment_id"),
        last_error: r.get("last_error"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    })
}
