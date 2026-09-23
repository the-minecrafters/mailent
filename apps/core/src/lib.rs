#![allow(
    clippy::collapsible_if,
    clippy::unnecessary_map_or,
    clippy::let_and_return
)]

pub mod api;
pub mod auth;
pub mod config;
pub mod dual_storage;
pub mod pipeline;
pub mod scheduler;
pub mod state;
pub mod training;

pub use config::CoreConfig;
pub use state::AppState;

pub mod probes;

pub mod evidence;

pub mod remediation;

pub mod integrations;

pub mod simulation;
