Mailent CLI for Linux x86_64 and Windows x86_64.

- Check mail domains, DNS settings, encryption, and certificates.
- Analyze local PCAP/PCAPNG files with Zeek.
- Connect a device to the workspace and sync results.
- Run scheduled checks locally with the optional systemd service.
- Export JSON, HTML, and PDF forensic reports.

Install on Linux:

```sh
curl -fsSL https://mailent.onrender.com/install.sh | bash
mailent login --server https://mailent.onrender.com
```

Install on Windows (PowerShell):

```powershell
irm https://mailent.onrender.com/install.ps1 | iex
mailent login --server https://mailent.onrender.com
```

Prebuilt binaries are provided for Linux x86_64 and Windows x86_64. Local capture analysis additionally requires Zeek 8+ (or Docker/Podman container runtime). The installer verifies SHA-256 checksums before installing.

The archives, checksums, and installer scripts are attached below. Full instructions: https://github.com/the-minecrafters/mailent/blob/main/docs/cli.md
