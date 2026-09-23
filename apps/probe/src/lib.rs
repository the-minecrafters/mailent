pub mod scope;
pub mod smtp;

pub use scope::{AuthorizedDomain, ProbeConfiguration, ProbeScope, ProbeScopeError, ProbeTarget};
pub use smtp::{
    ProbeLimits, SmtpProbeError, probe_imap_starttls, probe_implicit_tls, probe_pop3_stls,
    probe_smtp_starttls,
};

mod certificate;
