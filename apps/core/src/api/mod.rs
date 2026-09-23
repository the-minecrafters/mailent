pub mod assessments;
pub mod assets;
pub mod baselines;
pub mod certificates;
pub mod findings;
pub mod health;
pub mod integrations;
pub mod intelligence;
pub mod investigations;
pub mod metrics;
pub mod observations;
pub mod posture;
pub mod probes;
pub mod remediation;
pub mod reports;
pub mod sensors;
pub mod sessions;
pub mod simulation;
pub mod training;

use axum::{
    Router,
    routing::{get, patch, post},
};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::health_handler))
        .route("/ready", get(health::ready_handler))
        .route(
            "/api/v1/decisions/check",
            post(health::check_decision_provider),
        )
        .route(
            "/api/v1/assessments",
            get(assessments::list_assessments_handler),
        )
        .route(
            "/api/v1/assessments/analyze",
            post(assessments::analyze_capture_handler)
                .layer(axum::extract::DefaultBodyLimit::max(70 * 1024 * 1024)),
        )
        .route(
            "/api/v1/assessments/{id}",
            get(assessments::get_assessment_handler),
        )
        .route(
            "/api/v1/observations",
            post(observations::submit_observation_handler),
        )
        .route(
            "/api/v1/observations/evaluate",
            post(observations::evaluate_observation_handler),
        )
        .route("/api/v1/sessions", get(sessions::list_sessions_handler))
        .route("/api/v1/sessions/{id}", get(sessions::get_session_handler))
        .route(
            "/api/v1/sessions/{id}/posture",
            get(posture::get_session_posture_handler),
        )
        .route("/api/v1/findings", get(findings::list_findings_handler))
        .route("/api/v1/findings/{id}", get(findings::get_finding_handler))
        .route("/api/v1/assets", get(assets::list_assets_handler))
        .route(
            "/api/v1/assets/{id}/remediations",
            get(remediation::list).post(remediation::start),
        )
        .route("/api/v1/remediations/{id}", get(remediation::get))
        .route(
            "/api/v1/remediations/{id}/applied",
            post(remediation::applied),
        )
        .route(
            "/api/v1/remediations/{id}/verify",
            post(remediation::verify),
        )
        .route("/api/v1/assets/{id}", get(assets::get_asset_handler))
        .route(
            "/api/v1/assets/{id}/drift",
            get(assets::list_asset_drift_handler),
        )
        .route(
            "/api/v1/assets/{id}/certificates",
            get(assets::list_asset_certificates_handler),
        )
        .route(
            "/api/v1/assets/{id}/sessions",
            get(assets::list_asset_sessions_handler),
        )
        .route(
            "/api/v1/assets/{id}/findings",
            get(assets::list_asset_findings_handler),
        )
        .route(
            "/api/v1/assets/{id}/intelligence",
            get(assets::get_asset_intelligence_handler),
        )
        .route(
            "/api/v1/assets/{id}/posture",
            get(posture::get_asset_posture_handler),
        )
        .route(
            "/api/v1/assets/{id}/posture/history",
            get(posture::get_asset_posture_history_handler),
        )
        .route(
            "/api/v1/assets/{id}/verification",
            get(assets::get_asset_verification_handler),
        )
        .route(
            "/api/v1/assets/{id}/report",
            get(reports::get_asset_report_handler),
        )
        .route(
            "/api/v1/investigations/{id}/report",
            get(reports::get_investigation_report_handler),
        )
        .route(
            "/api/v1/reports/archive",
            post(reports::archive_report_handler),
        )
        .route(
            "/api/v1/reports/archived",
            get(reports::list_archived_reports_handler),
        )
        .route(
            "/api/v1/reports/archived/{id}",
            get(reports::get_archived_report_handler),
        )
        .route(
            "/api/v1/assets/{id}/baseline",
            get(baselines::get_asset_baseline_handler),
        )
        .route(
            "/api/v1/assets/{id}/anomalies",
            get(baselines::list_asset_anomalies_handler),
        )
        // Active probe routes
        .route(
            "/api/v1/assets/{id}/probe",
            post(probes::trigger_probe_handler),
        )
        .route(
            "/api/v1/assets/{id}/probes",
            get(probes::list_probes_for_asset_handler),
        )
        .route("/api/v1/probes", get(probes::list_recent_probes_handler))
        .route("/api/v1/probes/{id}", get(probes::get_probe_handler))
        .route("/api/v1/anomalies", get(baselines::list_anomalies_handler))
        .route("/api/v1/drift", get(assets::list_drift_events_handler))
        .route(
            "/api/v1/certificates",
            get(certificates::list_certificates_handler),
        )
        .route(
            "/api/v1/certificates/{fingerprint}",
            get(certificates::get_certificate_handler),
        )
        .route("/api/v1/sensors", get(sensors::list_sensors_handler))
        .route(
            "/api/v1/sensors/heartbeat",
            post(sensors::record_heartbeat_handler),
        )
        .route(
            "/api/v1/intelligence/{domain}",
            get(intelligence::get_domain_intelligence_handler),
        )
        .route(
            "/api/v1/intelligence/{domain}/refresh",
            post(intelligence::refresh_domain_intelligence_handler),
        )
        .route(
            "/api/v1/tls-rpt/reports",
            post(intelligence::import_tls_rpt_report_handler),
        )
        .route(
            "/api/v1/investigations",
            get(investigations::list_investigations_handler),
        )
        .route(
            "/api/v1/investigations/{id}",
            get(investigations::get_investigation_handler),
        )
        .route(
            "/api/v1/investigations/{id}/posture",
            get(posture::get_investigation_posture_handler),
        )
        .route(
            "/api/v1/investigations/{id}/status",
            patch(investigations::update_investigation_status_handler),
        )
        .route(
            "/api/v1/decisions",
            get(investigations::list_decisions_handler),
        )
        .route(
            "/api/v1/metrics/coverage",
            get(metrics::get_coverage_metrics_handler),
        )
        .route(
            "/api/v1/training",
            get(training::list_training_records_handler),
        )
        .route(
            "/api/v1/training/export",
            get(training::export_training_records_handler),
        )
        .route(
            "/api/v1/training/{id}",
            get(training::get_training_record_handler),
        )
        .route(
            "/api/v1/training/{id}/label",
            post(training::attach_analyst_label_handler),
        )
        // Practical crypto digital twin & policy simulation
        .route("/api/v1/policies", get(simulation::list_policies_handler))
        .route(
            "/api/v1/policies/simulate",
            post(simulation::simulate_policy_handler),
        )
        // Workflow integrations (Webhooks & Syslog CEF)
        .route(
            "/api/v1/integrations",
            get(integrations::list_integrations_handler)
                .post(integrations::create_integration_handler),
        )
        .route(
            "/api/v1/integrations/{id}",
            get(integrations::get_integration_handler)
                .put(integrations::update_integration_handler)
                .delete(integrations::delete_integration_handler),
        )
        .route(
            "/api/v1/integrations/{id}/test",
            post(integrations::test_integration_handler),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
