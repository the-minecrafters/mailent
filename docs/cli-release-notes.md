Mailent CLI for Linux x86_64.

- Check mail domains, DNS settings, encryption, and certificates.
- Analyze local PCAP/PCAPNG files with Zeek.
- Connect a device to the workspace and sync results.
- Run scheduled checks locally with the optional systemd service.
- Export JSON, HTML, and PDF reports.

Install:

```sh
curl -fsSL https://mailent.onrender.com/install.sh | bash
mailent login --server https://mailent.onrender.com
```

Requires Linux x86_64, glibc 2.35+, and OpenSSL 3. Local capture analysis additionally requires Zeek 8+. The installer verifies SHA-256 before installing to `~/.local/bin`; it does not start services or sign you in. Other platforms can build from source but have no prebuilt binary in this release.

The archive, checksum, and installer are attached below. Full instructions: https://github.com/the-minecrafters/mailent/blob/main/docs/cli.md
