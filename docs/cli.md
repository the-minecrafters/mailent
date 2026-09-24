# Mailent CLI

Check mail domains, analyze packet captures, and connect a device to your Mailent workspace.

## Install

Linux x86_64 with glibc 2.35 or newer and OpenSSL 3 (Ubuntu 22.04+, Debian 12+, and compatible distributions):

```sh
curl -fsSL https://mailent.onrender.com/install.sh | bash
```

The installer checks the download against its SHA-256 checksum and installs to `~/.local/bin`. It does not use sudo, edit your shell profile, start background services, or sign you in. Add that directory to your PATH if prompted. Bash, curl, tar, and sha256sum are required. macOS, Windows, ARM, and Alpine/musl binaries are not included in this release.

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
```

Only check domains you own or have permission to test. Zeek 8+ is required for Mailent. The installer verifies native Zeek or pulls the official Zeek 8.0.4 container using an installed Podman or Docker runtime. Setup fails if neither is available; it never reports a partial installation as ready. Use `--server` with your own deployment when applicable.

To run scheduled checks from this machine on Linux with systemd:

```sh
mailent agent install
mailent agent status
```

Installing a background service is a separate, explicit step. `mailent agent run` runs in the foreground instead. Use `mailent agent uninstall` before removing the binary if you installed the service.

## Build from source

With Rust 1.94+, protobuf compiler, pkg-config, and OpenSSL development headers installed:

```sh
cargo build --locked --release -p mailent
./target/release/mailent --version
```

## Live traffic and free device checks

`mailent monitor --interface eth0` runs Zeek on an interface that sees your mail-server traffic and sends normalized connection evidence to your signed-in workspace. Native Zeek needs packet-capture permissions; the container runner needs a rootful runtime for live capture. Rootless Podman supports PCAP analysis. Mailent never elevates privileges automatically. Live monitoring stops if access is revoked, local credentials change, or workspace access cannot be verified. Unsent observations are held in a bounded memory queue; they are not a durable disk archive.

For scheduled active checks, run `mailent agent install` and select that device when setting up monitoring in the workspace. The domain-check dialog also lets you select a connected device for a one-off check. Results return over HTTPS, so the workspace does not need SMTP access. This costs no additional hosting fee, but the selected machine must be able to reach the target mail server. Port 587 is not a substitute for an MX server's port 25. No TLS score or handshake is reported for unreachable servers.

Revoking a device from the web immediately rejects its API access and cancels queued jobs. Running CLI monitoring checks access every two seconds and clears revoked credentials before stopping. Local, offline PCAP analysis remains available without signing in. After upgrading, restart an installed service with `mailent agent restart` to load the new binary.
