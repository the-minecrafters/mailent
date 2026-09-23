pub mod scope;
pub mod smtp;

pub use scope::{AuthorizedDomain, ProbeConfiguration, ProbeScope, ProbeScopeError, ProbeTarget};
pub use smtp::{ProbeLimits, SmtpProbeError, probe_smtp_starttls};
