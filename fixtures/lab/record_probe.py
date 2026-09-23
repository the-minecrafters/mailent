"""Record a transport-only SMTP conversation in the running probe lab.
Usage: python3 record_probe.py /tmp/passive.pcap 12526 [TLSv1|TLSv1.1|TLSv1.2|TLSv1.3]
No authentication or mail commands. Capture requires the lab's tcpdump capability.
"""
import signal
import smtplib
import ssl
import subprocess
import sys
import time

path, port = sys.argv[1], int(sys.argv[2])
version = sys.argv[3] if len(sys.argv) > 3 else "TLSv1.3"
capture = subprocess.Popen(
    ["tcpdump", "--immediate-mode", "-i", "lo", "-U", "-s", "0", "-w", path, "tcp", "port", str(port)],
    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
)
while True:
    line = capture.stderr.readline()
    if b"listening on" in line:
        break
    if not line:
        raise RuntimeError(f"tcpdump did not start (exit {capture.poll()}): use a fresh writable capture path and CAP_NET_RAW")
try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Deliberately expired, self-signed lab certificate.
    versions = {"TLSv1": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1,
                "TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}
    context.minimum_version = context.maximum_version = versions[version]
    context.set_ciphers("ALL:@SECLEVEL=0")  # Explicit weak-protocol lab challenges only.
    with smtplib.SMTP("127.0.0.1", port, timeout=5) as client:
        client.ehlo("mailent-probe-lab")
        client.starttls(context=context)
    time.sleep(0.2)
finally:
    capture.send_signal(signal.SIGINT)
    capture.wait(timeout=5)
    if capture.returncode:
        raise RuntimeError(capture.stderr.read().decode())
print(path)
