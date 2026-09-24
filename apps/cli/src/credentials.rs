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
    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return PathBuf::from(appdata).join("mailent").join("credentials.json");
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            return PathBuf::from(profile)
                .join(".config")
                .join("mailent")
                .join("credentials.json");
        }
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

/// A running process must stop using credentials removed or replaced by another CLI.
pub fn still_current(expected: &DeviceCredentials) -> bool {
    load_credentials().is_some_and(|c| {
        c.device_id == expected.device_id
            && c.device_token == expected.device_token
            && c.server_url == expected.server_url
    })
}

/// Never erase a newer login when an older process receives a rejection.
pub fn handle_rejection(
    status: reqwest::StatusCode,
    creds: &DeviceCredentials,
) -> Result<bool, String> {
    if status != reqwest::StatusCode::UNAUTHORIZED && status != reqwest::StatusCode::FORBIDDEN {
        return Ok(false);
    }
    if still_current(creds) {
        clear_credentials().map_err(|e| format!("Cannot remove revoked credentials: {e}"))?;
    }
    eprintln!(
        "Device access has been revoked. Signed out; monitoring stopped. Run 'mailent login' to reconnect."
    );
    Ok(true)
}
