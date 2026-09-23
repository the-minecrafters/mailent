use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmailProtocol {
    Smtp,
    Imap,
    Pop3,
    Unknown,
}

impl std::fmt::Display for EmailProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smtp => write!(f, "SMTP"),
            Self::Imap => write!(f, "IMAP"),
            Self::Pop3 => write!(f, "POP3"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartTlsState {
    Advertised,
    Requested,
    Accepted,
    TlsStarted,
    TlsEstablished,
    AdvertisedAndUsed,
    AdvertisedNotUsed,
    NotAdvertised,
    Rejected,
    FailedHandshake,
    PlaintextContinuation,
}

impl std::fmt::Display for StartTlsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Advertised => write!(f, "advertised"),
            Self::Requested => write!(f, "requested"),
            Self::Accepted => write!(f, "accepted"),
            Self::TlsStarted => write!(f, "tls_started"),
            Self::TlsEstablished => write!(f, "tls_established"),
            Self::AdvertisedAndUsed => write!(f, "advertised_and_used"),
            Self::AdvertisedNotUsed => write!(f, "advertised_not_used"),
            Self::NotAdvertised => write!(f, "not_advertised"),
            Self::Rejected => write!(f, "rejected"),
            Self::FailedHandshake => write!(f, "failed_handshake"),
            Self::PlaintextContinuation => write!(f, "plaintext_continuation"),
        }
    }
}
