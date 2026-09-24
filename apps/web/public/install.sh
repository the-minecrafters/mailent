#!/usr/bin/env bash
# Install the released Mailent CLI. No source checkout or administrator access required.
set -euo pipefail

main() {
  local os arch asset release_url install_dir version expected actual zeek_output zeek_major runtime
  os=$(uname -s)
  arch=$(uname -m)
  if [[ "$os" != Linux || "$arch" != x86_64 ]]; then
    printf 'Mailent currently provides a Linux x86_64 release. Detected: %s %s\n' "$os" "$arch" >&2
    return 1
  fi
  for tool in curl tar sha256sum mktemp install; do
    command -v "$tool" >/dev/null 2>&1 || { printf 'Required command missing: %s\n' "$tool" >&2; return 1; }
  done
  version=${MAILENT_VERSION:-latest}
  if [[ "$version" != latest && ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
    printf 'MAILENT_VERSION must be a release tag such as v0.1.0.\n' >&2
    return 1
  fi
  install_dir=${MAILENT_INSTALL_DIR:-"${HOME:?HOME must be set}/.local/bin"}
  asset=mailent-linux-x86_64.tar.gz
  release_url=https://github.com/the-minecrafters/mailent/releases
  if [[ "$version" == latest ]]; then
    release_url=$release_url/latest/download
  else
    release_url=$release_url/download/$version
  fi
  mailent_work_dir=$(mktemp -d)
  mailent_staging=''
  trap 'rm -rf -- "$mailent_work_dir"; if [[ -n "$mailent_staging" ]]; then rm -f -- "$mailent_staging"; fi' EXIT
  printf 'Downloading Mailent (%s) for Linux x86_64…\n' "$version"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 180 "$release_url/$asset" -o "$mailent_work_dir/$asset"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 60 "$release_url/$asset.sha256" -o "$mailent_work_dir/$asset.sha256"
  read -r expected _ < "$mailent_work_dir/$asset.sha256"
  if [[ ! "$expected" =~ ^[a-fA-F0-9]{64}$ ]]; then
    printf 'The release checksum is invalid. Nothing was installed.\n' >&2
    return 1
  fi
  actual=$(sha256sum "$mailent_work_dir/$asset")
  actual=${actual%% *}
  if [[ "${expected,,}" != "$actual" ]]; then
    printf 'Checksum verification failed. Nothing was installed.\n' >&2
    return 1
  fi
  # Extract a single named member to stdout; never follow archive paths or links.
  tar -xOzf "$mailent_work_dir/$asset" mailent > "$mailent_work_dir/mailent"
  chmod 755 "$mailent_work_dir/mailent"
  if ! "$mailent_work_dir/mailent" --version; then
    printf 'Mailent could not run. This release requires Linux x86_64, glibc 2.35+, and OpenSSL 3. Nothing was installed.\n' >&2
    return 1
  fi
  tar -xOzf "$mailent_work_dir/$asset" mailent-zeek > "$mailent_work_dir/mailent-zeek"
  chmod 755 "$mailent_work_dir/mailent-zeek"
  zeek_output=$("${MAILENT_ZEEK:-zeek}" --version 2>&1 || true)
  zeek_major=$(printf '%s' "$zeek_output" | sed -nE 's/.*version ([0-9]+)\..*/\1/p' | head -n 1)
  if [[ "$zeek_major" =~ ^[0-9]+$ ]] && (( zeek_major >= 8 )); then
    printf 'Required Zeek is ready: %s\n' "$zeek_output"
  else
    runtime=${MAILENT_CONTAINER_RUNTIME:-}
    if [[ -z "$runtime" ]]; then
      for tool in podman docker; do
        if command -v "$tool" >/dev/null 2>&1; then runtime=$tool; break; fi
      done
    fi
    case "$runtime" in
      podman|docker) ;;
      *) printf 'Zeek 8+ is required. Install Zeek, Podman, or Docker, then run this installer again. Nothing was installed.\n' >&2; return 1 ;;
    esac
    printf 'Setting up required Zeek 8.0.4 with %s…\n' "$runtime"
    "$runtime" pull docker.io/zeek/zeek:8.0.4
    MAILENT_CONTAINER_RUNTIME="$runtime" "$mailent_work_dir/mailent-zeek" --version
  fi
  mkdir -p -- "$install_dir"
  install -m 755 "$mailent_work_dir/mailent-zeek" "$install_dir/mailent-zeek"
  mailent_staging=$(mktemp "$install_dir/.mailent-install.XXXXXX")
  install -m 755 "$mailent_work_dir/mailent" "$mailent_staging"
  mv -f -- "$mailent_staging" "$install_dir/mailent"
  mailent_staging=''
  printf '\nInstalled to %s/mailent\n' "$install_dir"
  case ":$PATH:" in
    *":$install_dir:"*) ;;
    *) printf 'Add this directory to your PATH:\n  export PATH=%q:"$PATH"\n' "$install_dir" ;;
  esac
  printf '\nConnect to your workspace:\n  mailent login --server https://mailent.onrender.com\n'
  printf '\nZeek is ready. Analyze a PCAP: mailent analyze capture.pcap\n'
  printf 'Monitor live mail traffic: mailent monitor --interface eth0\n'
  printf 'Live capture requires native Zeek capture permissions or a rootful container runtime.\n'
  printf 'Run scheduled server checks: mailent agent install\n'
  # Cleanup while the local variables are still in scope, including when piped to bash.
  rm -rf -- "$mailent_work_dir"
  trap - EXIT
}
main "$@"
