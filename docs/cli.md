# Mailent CLI

Mailent CLI is the primary product: analyze captured traffic, actively scan mail infrastructure, and continuously monitor live traffic on your machine. Sync structured results to Mailent Workspace for AI-assisted review, assessment history, drift, investigations, remediation tracking, and reports.

## Install

Linux x86_64 with glibc 2.35 or newer and OpenSSL 3 (Ubuntu 22.04+, Debian 12+, and compatible distributions):

```sh
curl -fsSL https://mailent.onrender.com/install.sh | bash
```

The installer checks the download against its SHA-256 checksum and installs to `~/.local/bin`. It does not use sudo, edit your shell profile, start background services, or sign you in. Add that directory to your PATH if prompted. Bash, curl, tar, and sha256sum are required. The shell installer targets Linux x86_64. Windows x64 uses the PowerShell installer shown on the website; macOS, ARM, and Alpine/musl binaries are not included.

To inspect the script before running it:

```sh
curl -fsSL https://mailent.onrender.com/install.sh -o install.sh
less install.sh
bash install.sh
```

For a custom destination or pinned version:

```sh
MAILENT_INSTALL_DIR="$HOME/bin" MAILENT_VERSION=v0.1.1 bash install.sh
```

Run the installer again to update. It verifies the new binary before replacing the installed version. Downloads and checksums are also available from [GitHub Releases](https://github.com/the-minecrafters/mailent/releases).

## Use

```sh
mailent --help
mailent login --server https://mailent.onrender.com
mailent status
mailent scan your-domain.com --sync
mailent analyze traffic.pcap --sync
mailent monitor --interface eth0
mailent fix TLS_LEGACY_VERSION --plan
sudo mailent fix TLS_LEGACY_VERSION --sync
```

Only check domains you own or have permission to test. Zeek 8+ is required for Mailent. The installer verifies native Zeek or pulls the official Zeek 8.0.4 container using an installed Podman or Docker runtime. Setup fails if neither is available; it never reports a partial installation as ready. Use `--server` with your own deployment when applicable.

The workspace does not upload PCAPs or run scans from the cloud. Remote scans are optional and available only while your CLI is online and explicitly accepting work. Install the CLI, run `mailent login`, and approve its code under **Mailent installations**. Connected installations unlock command guidance in the workspace; they do not need to run a job-polling daemon.

Use `mailent analyze <capture.pcap> --sync` and `mailent scan <domain> --sync` to analyze locally and submit structured assessments and evidence. Without `--sync`, these commands retain their local output workflows. `mailent monitor --interface <iface>` continuously submits structured connection evidence while running. Raw packet captures stay local in these workflows.

### Safe Server Remediation (`mailent fix`)

`mailent fix` safely remediates supported mail server findings (Postfix and Dovecot) with guaranteed rollback safety:

```sh
# Dry run: view planned configuration diff and verification steps
mailent fix TLS_LEGACY_VERSION --plan

# Auto-remediate Postfix or Dovecot locally and verify with live challenge probes
sudo mailent fix TLS_LEGACY_VERSION

# Auto-remediate and synchronize verified record and probe evidence to workspace
sudo mailent fix TLS_LEGACY_VERSION --sync

# Restore configuration from backup if needed
sudo mailent fix --rollback /etc/postfix/main.cf.mailent-backup-20260925...
```

Safety workflow:
1. **Timestamped backup**: Backs up original config before any modification.
2. **Atomic staging**: Changes written via tempfile and atomic filesystem rename.
3. **Pre-reload validation**: Runs `postfix check` or `doveconf -n` syntax check before reload.
4. **Automatic rollback**: On syntax check failure, the backup is restored immediately without service disruption.
5. **Active probe verification**: Sends active TLS 1.0 and 1.1 challenge probes to verify explicit server protocol refusal.

`mailent status`, `mailent doctor`, and `mailent logout` remain available for connection checks, required Zeek diagnostics, and revoking local access.

## Build from source

With Rust 1.94+, protobuf compiler, pkg-config, and OpenSSL development headers installed:

```sh
cargo build --locked --release -p mailent
./target/release/mailent --version
```

## Live traffic and installation access

`mailent monitor --interface eth0` runs Zeek on an interface that sees your mail-server traffic and sends normalized connection evidence to your signed-in workspace. Native Zeek needs packet-capture permissions; the container runner needs a rootful runtime for live capture. Rootless Podman supports PCAP analysis. Mailent never elevates privileges automatically. Live monitoring stops if access is revoked, local credentials change, or workspace access cannot be verified. Unsent observations are held in a bounded memory queue; they are not a durable disk archive.

Run infrastructure checks with `mailent scan <domain> --sync` from a machine that can reach the mail server. The workspace does not need outbound SMTP access. Port 587 is not a substitute for an MX server’s port 25, and unreachable servers remain inconclusive.

Revoking an installation rejects its API access. Local offline analysis remains available without signing in; syncing requires a current connection. Live monitoring stops when workspace access is revoked or cannot be verified.

### Optional remote scans

For optional remote scans, keep `mailent agent run` open on a connected machine. The workspace offers that installation only while its worker heartbeat is fresh; login and status checks do not mark it online. Checks that were not picked up promptly expire instead of running unexpectedly on reconnect. Local commands remain the primary workflow. Run `mailent agent uninstall` to remove a previously installed background polling service.

The workspace accepts structured CLI results. It does not process raw PCAP uploads, scan from the cloud, or schedule cloud network checks. Assessment history and comparisons are built from synced results.
