use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    #[serde(rename = "TLSv1.0")]
    Tls10,
    #[serde(rename = "TLSv1.1")]
    Tls11,
    #[serde(rename = "TLSv1.2")]
    Tls12,
    #[serde(rename = "TLSv1.3")]
    Tls13,
    #[serde(untagged)]
    Unknown(String),
}

impl TlsVersion {
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::Tls10 | Self::Tls11)
    }

    pub fn is_modern(&self) -> bool {
        matches!(self, Self::Tls12 | Self::Tls13)
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tls10 => write!(f, "TLSv1.0"),
            Self::Tls11 => write!(f, "TLSv1.1"),
            Self::Tls12 => write!(f, "TLSv1.2"),
            Self::Tls13 => write!(f, "TLSv1.3"),
            Self::Unknown(v) => write!(f, "{}", v),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CipherSuite {
    pub id: Option<u16>,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyExchange {
    Ecdhe,
    Dhe,
    RsaStatic,
    HybridPqc(String),
    #[serde(untagged)]
    Unknown(String),
}

impl KeyExchange {
    pub fn provides_forward_secrecy(&self) -> ForwardSecrecyState {
        match self {
            Self::Ecdhe | Self::Dhe | Self::HybridPqc(_) => ForwardSecrecyState::Supported,
            Self::RsaStatic => ForwardSecrecyState::NotSupported,
            Self::Unknown(_) => ForwardSecrecyState::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardSecrecyState {
    Supported,
    NotSupported,
    Unknown,
}
