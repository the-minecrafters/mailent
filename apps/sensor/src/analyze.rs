use crate::{SensorError, normalize};
use mailent_domain::NormalizedObservation;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

#[derive(Debug, Serialize)]
pub struct Analysis {
    pub capture_sha256: String,
    pub zeek_version: String,
    pub observations: Vec<NormalizedObservation>,
    pub warnings: Vec<String>,
}

/// Isolate each run, bound its input/runtime, and never replace Zeek errors with demo data.
pub async fn analyze(
    capture: &Path,
    zeek: &Path,
    sensor_id: &str,
    ignore_checksums: bool,
) -> Result<Analysis, SensorError> {
    let zeek = if zeek.components().count() > 1 {
        if !zeek.exists() {
            return Err(SensorError::Zeek(format!(
                "Zeek executable '{}' not found; install Zeek or pass --zeek scripts/zeek-container",
                zeek.display()
            )));
        }
        zeek.canonicalize()?
    } else {
        PathBuf::from(zeek)
    };
    let work = tempfile::tempdir()?;
    let mut input = tokio::fs::File::open(capture).await?;
    if input.metadata().await?.len() > 256 * 1024 * 1024 {
        return Err(SensorError::Input(
            "local captures are limited to 256 MiB".into(),
        ));
    }
    let mut copy = tokio::fs::File::create(work.path().join("capture.pcap")).await?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut size = 0usize;
    loop {
        let n = input.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        size += n;
        if size > 256 * 1024 * 1024 {
            return Err(SensorError::Input("capture grew beyond 256 MiB".into()));
        }
        hash.update(&buffer[..n]);
        copy.write_all(&buffer[..n]).await?;
    }
    copy.flush().await?;
    drop(copy);
    if size == 0 {
        return Err(SensorError::Input(
            "capture file is empty (not a valid PCAP header)".into(),
        ));
    }
    let capture_sha256 = format!("{:x}", hash.finalize());
    tokio::fs::create_dir(work.path().join("mailent")).await?;
    tokio::fs::write(
        work.path().join("mailent/__load__.zeek"),
        include_str!("../../../zeek/mailent/__load__.zeek"),
    )
    .await?;
    tokio::fs::write(
        work.path().join("mailent/dpd.sig"),
        include_str!("../../../zeek/mailent/dpd.sig"),
    )
    .await?;
    let version = run(&zeek, &["--version"], work.path()).await?;
    let raw_version = String::from_utf8_lossy(&version.stdout).trim().to_string();
    if !(raw_version.to_lowercase().contains("zeek") && raw_version.contains("version")) {
        return Err(SensorError::Zeek(format!(
            "executable did not identify itself as Zeek (got: '{raw_version}')"
        )));
    }
    let zeek_version = if let Some(idx) = raw_version.find("version ") {
        format!("zeek {}", &raw_version[idx..])
    } else {
        raw_version
    };
    let mut args = vec!["-b", "-D", "-r", "capture.pcap", "mailent"];
    if ignore_checksums {
        args.push("-C");
    }
    let output = run(&zeek, &args, work.path()).await?;
    let mut warnings = Vec::new();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        warnings.push(stderr);
    }
    let mut observations =
        normalize::normalize(work.path(), &capture_sha256, sensor_id, &zeek_version)?;
    if ignore_checksums {
        warnings.push("Packet checksum validation disabled explicitly (-C)".into());
    }
    if observations.is_empty() {
        warnings.push(
            "No email sessions found; capture may be empty, non-mail, or missing protocol evidence"
                .into(),
        );
    }
    for observation in &mut observations {
        if let Some(capture) = &mut observation.capture {
            capture.gaps.extend(
                warnings
                    .iter()
                    .filter(|w| !w.contains("No email sessions"))
                    .cloned(),
            );
        }
    }
    Ok(Analysis {
        capture_sha256,
        zeek_version,
        observations,
        warnings,
    })
}

async fn run(zeek: &Path, args: &[&str], dir: &Path) -> Result<std::process::Output, SensorError> {
    let is_script = cfg!(windows)
        && zeek
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat"));

    let mut cmd = if is_script {
        let mut c = Command::new("cmd.exe");
        c.arg("/c").arg(zeek);
        c
    } else {
        Command::new(zeek)
    };
    cmd.args(args)
        .current_dir(dir)
        .env("ZEEK_DNS_FAKE", "1")
        .kill_on_drop(true);

    let result = tokio::time::timeout(Duration::from_secs(120), cmd.output())
        .await
        .map_err(|_| SensorError::Zeek("Zeek exceeded the 120 second local analysis limit".into()))?;
    let output=result.map_err(|e|if e.kind()==std::io::ErrorKind::NotFound {SensorError::Zeek(format!("Zeek executable '{}' not found; install Zeek or pass --zeek scripts/zeek-container",zeek.display()))}else{SensorError::Io(e)})?;
    if !output.status.success() {
        return Err(SensorError::Zeek(format!(
            "Zeek exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    // libpcap can report read corruption without a failing exit status on some releases.
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if stderr.contains("error") || stderr.contains("truncated dump") {
        return Err(SensorError::Zeek(
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ));
    }
    Ok(output)
}
