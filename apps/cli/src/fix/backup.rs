use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Creates a timestamped backup of the configuration file.
/// Format: <config_path>.mailent-backup-<timestamp>
pub fn create_backup(config_path: &Path) -> Result<PathBuf, String> {
    if !config_path.exists() {
        return Err(format!(
            "Configuration file does not exist: {}",
            config_path.display()
        ));
    }

    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| format!("Failed to format timestamp: {e}"))?
        .replace([':', '-'], "");

    let file_name = config_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("config");

    let backup_name = format!("{file_name}.mailent-backup-{timestamp}");
    let backup_path = config_path
        .parent()
        .map(|p| p.join(&backup_name))
        .unwrap_or_else(|| PathBuf::from(&backup_name));

    fs::copy(config_path, &backup_path).map_err(|e| {
        format!(
            "Failed to back up {} to {}: {e}",
            config_path.display(),
            backup_path.display()
        )
    })?;

    // Preserve permissions if on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(config_path) {
            let mode = metadata.permissions().mode();
            let _ = fs::set_permissions(&backup_path, fs::Permissions::from_mode(mode));
        }
    }

    Ok(backup_path)
}

/// Atomically writes new content to `config_path` by writing to a temporary file
/// in the same directory, syncing to disk, and renaming it over `config_path`.
pub fn atomic_write(config_path: &Path, content: &str) -> Result<(), String> {
    let parent = config_path.parent().unwrap_or_else(|| Path::new("."));

    let mut temp_file = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
        format!(
            "Failed to create temporary file in {}: {e}",
            parent.display()
        )
    })?;

    temp_file
        .write_all(content.as_bytes())
        .map_err(|e| format!("Failed to write configuration content: {e}"))?;

    temp_file
        .as_file()
        .sync_all()
        .map_err(|e| format!("Failed to sync configuration to storage: {e}"))?;

    // Preserve original permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(config_path) {
            let mode = metadata.permissions().mode();
            let _ = fs::set_permissions(temp_file.path(), fs::Permissions::from_mode(mode));
        }
    }

    temp_file.persist(config_path).map_err(|e| {
        format!(
            "Failed to atomically persist configuration to {}: {e}",
            config_path.display()
        )
    })?;

    Ok(())
}

/// Restores a configuration file from a backup copy.
pub fn restore_backup(backup_path: &Path, config_path: &Path) -> Result<(), String> {
    if !backup_path.exists() {
        return Err(format!(
            "Backup file does not exist: {}",
            backup_path.display()
        ));
    }

    fs::copy(backup_path, config_path).map_err(|e| {
        format!(
            "Failed to restore {} from {}: {e}",
            config_path.display(),
            backup_path.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(backup_path) {
            let mode = metadata.permissions().mode();
            let _ = fs::set_permissions(config_path, fs::Permissions::from_mode(mode));
        }
    }

    Ok(())
}
