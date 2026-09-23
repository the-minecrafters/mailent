//! Domain Mail Infrastructure Scanner crate.
//!
//! Orchestrates DNS/MX discovery, SRV service discovery, active TLS/STARTTLS probing,
//! external policy correlation (MTA-STS, DANE, TLS-RPT, DNSSEC), and deterministic
//! posture evaluation into unified Infrastructure Assessments and Forensic Reports.

pub mod scanner;

pub use scanner::{DomainScanner, DomainScannerConfig, InfrastructureScanResult, ScannerError};
