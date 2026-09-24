#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cmp "$repo/scripts/install.sh" "$repo/apps/web/public/install.sh"
bash -n "$repo/scripts/install.sh"
mkdir -p "$work/mock" "$work/package" "$work/assets"
cat > "$work/package/mailent" <<'BIN'
#!/usr/bin/env bash
printf 'mailent 0.1.0\n'
BIN
cp "$repo/scripts/mailent-zeek" "$work/package/mailent-zeek"
chmod +x "$work/package/mailent"
tar -C "$work/package" -czf "$work/assets/mailent-linux-x86_64.tar.gz" mailent mailent-zeek
(cd "$work/assets" && sha256sum mailent-linux-x86_64.tar.gz > mailent-linux-x86_64.tar.gz.sha256)
cat > "$work/mock/curl" <<'CURL'
#!/usr/bin/env bash
set -eu
[[ "${MOCK_MISSING:-0}" == 0 ]] || exit 22
url=''; destination=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    https://*) url=$1; shift ;;
    -o) destination=$2; shift 2 ;;
    *) shift ;;
  esac
done
[[ "$url" == https://github.com/the-minecrafters/mailent/releases/* ]]
cp "$MOCK_ASSETS/${url##*/}" "$destination"
CURL
cat > "$work/mock/uname" <<'UNAME'
#!/usr/bin/env bash
case "$1" in
  -s) printf '%s\n' "${MOCK_OS:-Linux}" ;;
  -m) printf '%s\n' "${MOCK_ARCH:-x86_64}" ;;
esac
UNAME
cat > "$work/mock/zeek" <<'ZEEK'
#!/usr/bin/env bash
[[ "${MOCK_NO_ZEEK:-0}" == 0 ]] || exit 1
printf 'zeek version 8.0.4\n'
ZEEK
chmod +x "$work/mock/"*
export PATH="$work/mock:$PATH" MOCK_ASSETS="$work/assets" MAILENT_INSTALL_DIR="$work/install path/bin"
bash "$repo/scripts/install.sh" > "$work/success.log"
[[ "$("$MAILENT_INSTALL_DIR/mailent" --version)" == 'mailent 0.1.0' ]]
MAILENT_VERSION=v0.1.0 bash "$repo/scripts/install.sh" > "$work/pinned.log"
printf 'previous binary\n' > "$MAILENT_INSTALL_DIR/mailent"
assert_failure() {
  if "$@" > "$work/error.log" 2>&1; then
    printf 'Expected failure: %s\n' "$*" >&2
    exit 1
  fi
  [[ "$(cat "$MAILENT_INSTALL_DIR/mailent")" == 'previous binary' ]]
  ! grep -q 'unbound variable' "$work/error.log"
}
assert_failure env MOCK_NO_ZEEK=1 MAILENT_CONTAINER_RUNTIME=missing bash "$repo/scripts/install.sh"
assert_failure env MOCK_OS=Darwin bash "$repo/scripts/install.sh"
assert_failure env MOCK_ARCH=aarch64 bash "$repo/scripts/install.sh"
assert_failure env MOCK_MISSING=1 bash "$repo/scripts/install.sh"
assert_failure env MAILENT_VERSION='../../other' bash "$repo/scripts/install.sh"
printf '%064d  mailent-linux-x86_64.tar.gz\n' 0 > "$work/assets/mailent-linux-x86_64.tar.gz.sha256"
assert_failure bash "$repo/scripts/install.sh"
grep -q 'Checksum verification failed' "$work/error.log"
printf 'Installer checks passed: latest, pinned version, path with spaces, unsupported platform, download failure, invalid version, checksum failure, previous binary preserved.\n'
