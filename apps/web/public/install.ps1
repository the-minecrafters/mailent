# PowerShell installer for Mailent CLI on Windows x64.
# Usage:
#   irm https://mailent.onrender.com/install.ps1 | iex

$ErrorActionPreference = 'Stop'

function Main {
    Write-Host "Mailent CLI Windows Installer" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor DarkGray

    # Verify architecture
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    if ($arch -ne [System.Runtime.InteropServices.Architecture]::X64) {
        Write-Error "Mailent for Windows currently supports x64 (64-bit AMD64). Detected: $arch"
        return
    }

    $version = if ($env:MAILENT_VERSION) { $env:MAILENT_VERSION } else { "latest" }
    $asset = "mailent-windows-x86_64.zip"

    $baseUrl = "https://github.com/the-minecrafters/mailent/releases"
    if ($version -eq "latest") {
        $downloadUrl = "$baseUrl/latest/download"
    } else {
        $downloadUrl = "$baseUrl/download/$version"
    }

    $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("mailent-install-" + [System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        $zipPath = Join-Path $tempDir $asset
        $shaPath = Join-Path $tempDir "$asset.sha256"

        Write-Host "Downloading Mailent ($version) for Windows x64..." -ForegroundColor Green
        Invoke-WebRequest -Uri "$downloadUrl/$asset" -OutFile $zipPath -UseBasicParsing
        Invoke-WebRequest -Uri "$downloadUrl/$asset.sha256" -OutFile $shaPath -UseBasicParsing

        $expectedHash = (Get-Content $shaPath).Trim().Split(" ")[0].ToLower()
        $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()

        if ($expectedHash -ne $actualHash) {
            Write-Error "SHA256 verification failed! Expected: $expectedHash, Actual: $actualHash"
            return
        }
        Write-Host "[✓] Checksum verified: $actualHash" -ForegroundColor Green

        Write-Host "Extracting Mailent archive in temporary workspace..." -ForegroundColor DarkGray
        Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

        $extractedExe = Join-Path $tempDir "mailent.exe"
        $extractedCmd = Join-Path $tempDir "mailent-zeek.cmd"

        if (-not (Test-Path $extractedExe)) {
            Write-Error "Downloaded archive did not contain mailent.exe"
            return
        }

        # Step 1: Verify binary self-test in tempDir before touching system
        Write-Host "Running binary self-test..." -ForegroundColor DarkGray
        $versionOutput = & $extractedExe --version
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Mailent executable failed self-test execution (exit code $LASTEXITCODE)."
            return
        }
        Write-Host "[✓] Executable verified: $versionOutput" -ForegroundColor Green

        # Step 2: Verify Zeek dependency before committing installation
        Write-Host "`nChecking Zeek 8+ dependency..." -ForegroundColor Cyan
        $hasZeek = $false
        try {
            $zeekOut = & zeek.exe --version 2>&1
            if ($LASTEXITCODE -eq 0 -and $zeekOut -match "version (\d+)\.") {
                $major = [int]$matches[1]
                if ($major -ge 8) {
                    Write-Host "[✓] Native Zeek 8+ found: $zeekOut" -ForegroundColor Green
                    $hasZeek = $true
                }
            }
        } catch { }

        if (-not $hasZeek) {
            $runtime = ""
            if (Get-Command podman -ErrorAction SilentlyContinue) {
                $runtime = "podman"
            } elseif (Get-Command docker -ErrorAction SilentlyContinue) {
                $runtime = "docker"
            }

            if ($runtime -ne "") {
                Write-Host "Configuring Zeek 8.0.4 via container runtime ($runtime)..." -ForegroundColor Yellow
                & $runtime pull docker.io/zeek/zeek:8.0.4
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "Failed to pull Zeek container image via $runtime (exit code $LASTEXITCODE)."
                    return
                }
                Write-Host "[✓] Zeek 8 container image ready." -ForegroundColor Green
                $hasZeek = $true
            } else {
                Write-Error "Mailent requires Zeek 8+ for passive network forensic analysis.`nNeither native zeek.exe (version 8+) nor a supported container runtime (Docker Desktop or Podman) was found.`n`nPlease install Docker Desktop or Podman, or install native Zeek 8+, then rerun this installer."
                return
            }
        }

        # Step 3: Only now create installDir, copy files, and update PATH
        $installDir = if ($env:MAILENT_INSTALL_DIR) {
            $env:MAILENT_INSTALL_DIR
        } elseif ($env:LOCALAPPDATA) {
            Join-Path $env:LOCALAPPDATA "Programs\Mailent\bin"
        } else {
            Join-Path $env:USERPROFILE ".mailent\bin"
        }

        if (-not (Test-Path $installDir)) {
            New-Item -ItemType Directory -Path $installDir -Force | Out-Null
        }

        Write-Host "Installing Mailent binaries to $installDir..." -ForegroundColor DarkGray
        Copy-Item -Path $extractedExe -Destination (Join-Path $installDir "mailent.exe") -Force

        if (Test-Path $extractedCmd) {
            Copy-Item -Path $extractedCmd -Destination (Join-Path $installDir "mailent-zeek.cmd") -Force
        }

        # Add to User PATH if not already present
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $pathList = if ($userPath) { $userPath -split ";" } else { @() }
        if ($pathList -notcontains $installDir) {
            Write-Host "Adding $installDir to user PATH..." -ForegroundColor DarkGray
            $newPath = if ($userPath) { "$userPath;$installDir" } else { $installDir }
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            $env:Path = "$env:Path;$installDir"
        }

        Write-Host "`nInstallation successful!" -ForegroundColor Green
        Write-Host "========================" -ForegroundColor DarkGray
        Write-Host "Binary location: $installDir\mailent.exe"
        Write-Host "`nGetting Started:"
        Write-Host "  1. Link to workspace:     mailent login --server https://mailent.onrender.com"
        Write-Host "  2. Scan a mail domain:    mailent scan example.com"
        Write-Host "  3. Analyze a capture:     mailent analyze capture.pcap"
        Write-Host "  4. Check diagnostics:     mailent doctor"
        Write-Host "`nNote: If 'mailent' is not recognized in current terminal, restart your PowerShell session." -ForegroundColor DarkGray
    } finally {
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Main
