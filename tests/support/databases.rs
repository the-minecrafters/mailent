//! Each integration test owns a fresh schema and analytical database.
use sqlx::postgres::PgPoolOptions;
pub struct TestDatabases {
    pub postgres_url: String,
    pub clickhouse_url: String,
    pub clickhouse_database: String,
    admin: sqlx::PgPool,
    schema: String,
}
impl TestDatabases {
    pub async fn start() -> Option<Self> {
        let base = std::env::var("MAILENT_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://mailent:mailent_dev_password@127.0.0.1:5432/mailent".into()
        });
        let admin = match PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect(&base)
            .await
        {
            Ok(pool) => pool,
            Err(error) => {
                assert!(
                    std::env::var_os("MAILENT_REQUIRE_DATABASES").is_none(),
                    "Required PostgreSQL unavailable: {error}"
                );
                eprintln!("Database integration skipped: {error}");
                return None;
            }
        };
        let schema = format!("test_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .expect("create isolated test schema");
        let separator = if base.contains('?') { '&' } else { '?' };
        let postgres_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
        let clickhouse_url = std::env::var("MAILENT_CLICKHOUSE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8123".into());
        Some(Self {
            postgres_url,
            clickhouse_url,
            clickhouse_database: schema.clone(),
            admin,
            schema,
        })
    }
    pub async fn finish(self) {
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .expect("drop only owned test schema");
        self.admin.close().await;
        let response = reqwest::Client::new()
            .post(format!("{}/?database=default", self.clickhouse_url))
            .body(format!(
                "DROP DATABASE IF EXISTS {}",
                self.clickhouse_database
            ))
            .send()
            .await;
        if std::env::var_os("MAILENT_REQUIRE_DATABASES").is_some() {
            response
                .expect("ClickHouse cleanup")
                .error_for_status()
                .expect("drop owned test database");
        }
    }
}
