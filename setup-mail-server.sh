#!/usr/bin/env bash
set -euo pipefail

# Ensure non-root binding to port 25 works seamlessly on Linux
if [ "$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)" -gt 25 ]; then
  if command -v sudo >/dev/null 2>&1; then
    sudo sysctl -w net.ipv4.ip_unprivileged_port_start=25 >/dev/null 2>&1 || true
  fi
fi

# Detect container engine (podman preferred, docker fallback)
ENGINE="podman"
if ! command -v podman >/dev/null 2>&1; then
  if command -v docker >/dev/null 2>&1; then
    ENGINE="docker"
  else
    echo "Error: neither podman nor docker found." >&2
    exit 1
  fi
fi

echo -e "\n── 󰇮 Deploying Mail Server from Scratch ──"
echo "  󰒓 Initializing Postfix & Dovecot services..."

# Remove any previously running container
$ENGINE rm -f mail-server >/dev/null 2>&1 || true

# Run container with standard and test mail ports
$ENGINE run -d --name mail-server \
  -p 25:25 \
  -p 12525:25 \
  -p 12993:993 \
  -p 12995:995 \
  -p 143:143 \
  mailent-lab python3 /lab/generate.py --serve >/dev/null

# Wait briefly for daemon startup
sleep 1.5

# Generate fresh valid certificate inside container (valid for 1 year)
$ENGINE exec mail-server python3 -c "
import datetime, ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mail.mailent.test')])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('mail.mailent.test'), x509.DNSName('localhost'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .sign(key, hashes.SHA256()))

Path('/tmp/lab.key').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
Path('/tmp/lab.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
" >/dev/null 2>&1 || true

# Set up initial vulnerable Postfix main.cf with legacy TLS 1.0 enabled
mkdir -p /tmp/postfix
cat << 'EOF' > /tmp/postfix/main.cf
myhostname = mail.mailent.test
mydestination = localhost
inet_interfaces = all
inet_protocols = ipv4
mynetworks = 127.0.0.0/8
smtpd_tls_security_level = may
smtpd_tls_cert_file = /tmp/lab.crt
smtpd_tls_key_file = /tmp/lab.key
smtpd_tls_protocols = >=TLSv1
smtpd_tls_ciphers = medium
tls_medium_cipherlist = ALL:@SECLEVEL=0
smtpd_relay_restrictions = reject
EOF

$ENGINE cp /tmp/postfix/main.cf mail-server:/etc/postfix/main.cf >/dev/null 2>&1 || true
$ENGINE exec mail-server postfix reload >/dev/null 2>&1 || true
$ENGINE exec mail-server doveadm reload >/dev/null 2>&1 || true

echo "  󰈙 Domain:     mail.mailent.test"
echo "  󰒋 Services:   Postfix (SMTP:25, 12525) & Dovecot (IMAPS:12993, POP3S:12995)"
echo "  󰌾 Security:   STARTTLS enabled (legacy TLS 1.0 profile for testing)"
echo "  󰈙 Config:     /tmp/postfix/main.cf"
echo -e "  󰄬 Status:     Online & listening on 127.0.0.1:25\n"
