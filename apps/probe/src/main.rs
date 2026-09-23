use clap::{Parser, Subcommand};
use mailent_probe::{ProbeConfiguration, ProbeLimits, probe_smtp_starttls};
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Mailent Active Probe — authorized SMTP / TLS verification
///
/// Never authenticates. Never sends mail. Enforces operator scope.
#[derive(Parser, Debug)]
#[command(name = "mailent-probe", about = "Mailent active SMTP/TLS verification")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Probe SMTP STARTTLS on an explicitly authorized host.
    Smtp {
        /// Target hostname or domain.
        target: String,
        /// Port to probe (default: 25).
        #[arg(short, long, default_value = "25")]
        port: u16,
    },
    /// Probe an implicit-TLS endpoint (SMTPS 465 / IMAPS 993 / POP3S 995).
    Tls {
        /// Target hostname.
        target: String,
        /// Port to probe (default: 465 for SMTPS).
        #[arg(short, long, default_value = "465")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mailent_probe=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();
    let config = ProbeConfiguration::from_env();
    let scope = config.to_scope();

    let limits = ProbeLimits {
        connect_timeout: Duration::from_secs(config.timeout_seconds),
        read_timeout: Duration::from_secs(config.timeout_seconds),
        ..Default::default()
    };

    match cli.command {
        Commands::Smtp { target, port } => {
            scope.validate(&target)?;
            tracing::info!(target = %target, port, "Starting SMTP STARTTLS probe");
            let hostname = "mailent-probe";
            match probe_smtp_starttls(&target, port, hostname, &limits, &scope).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                    if result.starttls == mailent_domain::ProbeStartTlsResult::AdvertisedAndAccepted
                    {
                        tracing::info!(
                            target = %target,
                            latency_ms = result.latency_ms,
                            cert_subject = ?result.certificate.as_ref().map(|c| &c.reference.subject),
                            "STARTTLS probe successful"
                        );
                    } else {
                        tracing::warn!(
                            target = %target,
                            starttls = ?result.starttls,
                            "STARTTLS not established"
                        );
                    }
                }
                Err(e) => {
                    if let mailent_probe::SmtpProbeError::Partial { evidence, .. } = &e {
                        println!("{}", serde_json::to_string_pretty(evidence)?);
                    }
                    tracing::error!(target = %target, error = %e, "Probe failed");
                    eprintln!("Probe failed: {e}");
                    std::process::exit(2);
                }
            }
        }
        Commands::Tls { target, port } => {
            scope.validate(&target)?;
            tracing::info!(target = %target, port, "Starting implicit-TLS probe");

            match mailent_probe::smtp::probe_implicit_tls(&target, port, &limits, &scope).await {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                Err(e) => {
                    if let mailent_probe::SmtpProbeError::Partial { evidence, .. } = &e {
                        println!("{}", serde_json::to_string_pretty(evidence)?);
                    }
                    tracing::error!(target = %target, error = %e, "Implicit-TLS probe failed");
                    eprintln!("Probe failed: {e}");
                    std::process::exit(2);
                }
            }
        }
    }

    Ok(())
}
