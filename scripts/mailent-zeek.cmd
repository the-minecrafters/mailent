@echo off
setlocal enabledelayedexpansion

rem Mailent Zeek 8 runner for Windows environments without native Zeek.
rem Checks for Docker Desktop or Podman and runs official Zeek container.

set "RUNTIME=%MAILENT_CONTAINER_RUNTIME%"

if "%RUNTIME%"=="" (
  where podman >nul 2>nul
  if not errorlevel 1 (
    set "RUNTIME=podman"
  ) else (
    where docker >nul 2>nul
    if not errorlevel 1 (
      set "RUNTIME=docker"
    )
  )
)

if "%RUNTIME%"=="" (
  echo Zeek requires Docker Desktop, Podman, or a native Zeek 8+ installation. >&2
  echo Install Docker Desktop or set MAILENT_ZEEK to your native zeek.exe. >&2
  exit /b 1
)

%RUNTIME% run --rm --network none -v "%cd%:/work" -w /work docker.io/zeek/zeek:8.0.4 zeek %*
exit /b %ERRORLEVEL%
