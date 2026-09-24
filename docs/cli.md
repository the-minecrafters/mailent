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
MAILENT_INSTALL_DIR="$HOME/bin" MAILENT_VERSION=v0.1.0 bash install.sh
```

Run the installer again to update. It verifies the new binary before replacing the installed version. Downloads and checksums are also available from [GitHub Releases](https://github.com/the-minecrafters/mailent/releases).

## Use

```sh
mailent --help
mailent login --server https://mailent.onrender.com
mailent status
mailent scan your-domain.com --sync
mailent analyze traffic.pcap --sync
```

Only check domains you own or have permission to test. Local capture analysis requires Zeek 8+. Domain checks do not require Zeek. Use `--server` with your own deployment when applicable.

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
