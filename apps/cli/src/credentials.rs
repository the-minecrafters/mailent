use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCredentials {
    pub server_url: String,
    pub device_id: Uuid,
    pub device_token: String,
    pub organization_id: Option<Uuid>,
    pub device_name: String,
    pub created_at: String,
}

pub fn credentials_path() -> PathBuf {
    if let Ok(custom) = std::env::var("MAILENT_CREDENTIALS_PATH") {
        return PathBuf::from(custom);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("mailent")
        .join("credentials.json")
}

pub fn load_credentials() -> Option<DeviceCredentials> {
    let path = credentials_path();
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn save_credentials(creds: &DeviceCredentials) -> io::Result<()> {
    let path = credentials_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(creds)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&path)?;
    use std::io::Write;
    file.write_all(json.as_bytes())?;
    file.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

pub fn clear_credentials() -> io::Result<()> {
    let path = credentials_path();
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}
