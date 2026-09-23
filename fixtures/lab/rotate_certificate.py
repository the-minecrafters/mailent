"""Explicit remediation lab operation: issue a trusted expired or valid leaf.
Run INSIDE the disposable Postfix/Dovecot fixture container, never a mail server.
Copies no production keys; the test CA lives only in /tmp and survives rotation.
Usage: python3 rotate_certificate.py expired|valid
Copy /tmp/remediation-ca.crt to the host and set SSL_CERT_FILE for the probe/core.
"""
import datetime
import ipaddress
import os
from pathlib import Path
import subprocess
import sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

assert len(sys.argv) == 2 and sys.argv[1] in ("expired", "valid")
now = datetime.datetime.now(datetime.timezone.utc)
ca_key_path = Path('/tmp/remediation-ca.key')
ca_path = Path('/tmp/remediation-ca.crt')

def write_key(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    os.chmod(path, 0o600)

if not ca_path.exists():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Mailent disposable remediation lab CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=30))
          .not_valid_after(now + datetime.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
    write_key(ca_key_path, ca_key)
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'mail.mailent.test')])
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca.subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=7))
        .not_valid_after(now + datetime.timedelta(days=7) if sys.argv[1] == 'valid' else now - datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('mail.mailent.test'), x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
write_key(Path('/tmp/lab.key'), key)
Path('/tmp/lab.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
subprocess.run(['postfix', 'reload'], check=True)
subprocess.run(['doveadm', 'reload'], check=True)
print(f"{sys.argv[1]} leaf SHA256 {cert.fingerprint(hashes.SHA256()).hex()}")
