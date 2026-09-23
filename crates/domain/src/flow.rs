use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkFlow {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
}

impl NetworkFlow {
    pub fn src_endpoint(&self) -> String {
        format_endpoint(&self.src_ip, self.src_port)
    }

    pub fn dst_endpoint(&self) -> String {
        format_endpoint(&self.dst_ip, self.dst_port)
    }
}

fn format_endpoint(ip: &str, port: u16) -> String {
    if ip.contains(':') && !ip.starts_with('[') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

impl std::fmt::Display for NetworkFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {}",
            format_endpoint(&self.src_ip, self.src_port),
            format_endpoint(&self.dst_ip, self.dst_port)
        )
    }
}
