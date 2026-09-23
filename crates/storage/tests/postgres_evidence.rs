use mailent_domain::{EmailSession, NormalizedObservation};
use mailent_storage::{ObservationRepository, PostgresStorage, SessionRepository};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

#[tokio::test]
async fn evidence_survives_reconnect_and_conflicts_do_not_overwrite() {
    let Ok(url) = std::env::var("MAILENT_TEST_DATABASE_URL") else {
        return;
    };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let schema = format!("test_evidence_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .unwrap();
    let options: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
    let options = options.options([("search_path", schema.clone())]);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .unwrap();
    let store = PostgresStorage::from_pool(pool.clone());
    store.migrate().await.unwrap();
    let observation: NormalizedObservation = serde_json::from_str(include_str!(
        "../../../fixtures/synthetic/smtp_tls10_legacy.json"
    ))
    .unwrap();
    let mut session = EmailSession::from(&observation);
    ObservationRepository::save(&store, observation.clone())
        .await
        .unwrap();
    SessionRepository::save(&store, session.clone())
        .await
        .unwrap();
    session.last_seen += time::Duration::seconds(3);
    SessionRepository::save(&store, session.clone())
        .await
        .unwrap();
    pool.close().await;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let store = PostgresStorage::from_pool(pool.clone());
    let result = async {
        assert_eq!(
            SessionRepository::find_by_id(&store, session.session_id).await?,
            Some(session.clone())
        );
        assert_eq!(
            ObservationRepository::find_by_id(&store, observation.observation_id).await?,
            Some(observation)
        );
        let mut conflict = session.clone();
        conflict.flow.dst_port = 999;
        assert!(SessionRepository::save(&store, conflict).await.is_err());
        assert_eq!(
            SessionRepository::find_by_id(&store, session.session_id).await?,
            Some(session)
        );
        Ok::<_, mailent_storage::StorageError>(())
    }
    .await;
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .unwrap();
    result.unwrap();
}
