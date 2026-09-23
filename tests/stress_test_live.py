#!/usr/bin/env python3
"""
Stress-tests the live Mailent cloud instance on Render (https://mailent.onrender.com).
Exercises health checks, authentication config, forensic PCAP upload across edge cases
including imap_starttls.pcap, concurrent analysis, and negative input validation.
"""

import base64
import concurrent.futures
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE_URL = os.environ.get("MAILENT_URL", "https://mailent.onrender.com").rstrip("/")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def http_get(path, headers=None):
    req = urllib.request.Request(f"{BASE_URL}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body

def http_post_json(path, data, headers=None):
    h = {"Content-Type": "application/json", "X-Mailent-Guest": "true"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(f"{BASE_URL}{path}", data=json.dumps(data).encode(), headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body

def find_fixture(relative_path):
    p1 = os.path.join(REPO_ROOT, relative_path)
    if os.path.exists(p1):
        return p1
    p2 = os.path.join(REPO_ROOT, "fixtures", relative_path)
    if os.path.exists(p2):
        return p2
    raise FileNotFoundError(f"Fixture not found: {relative_path}")

def run_stress_test():
    log(f"Starting live stress test against {BASE_URL}")

    # 1. Health check
    log("Checking /health...")
    status, body = http_get("/health")
    assert status == 200, f"Health check failed with {status}: {body}"
    log(f"Health check OK: {body}")

    # 2. Auth config
    log("Checking /auth/config...")
    status, body = http_get("/auth/config")
    assert status == 200, f"Auth config failed with {status}: {body}"
    log(f"Auth config OK (enabled={body.get('enabled')})")

    # 3. Test imap_starttls.pcap (User's failed test)
    imap_path = find_fixture("pcap/imap_starttls.pcap")
    with open(imap_path, "rb") as f:
        imap_b64 = base64.b64encode(f.read()).decode()

    log(f"Uploading imap_starttls.pcap ({len(imap_b64)} b64 bytes)...")
    t0 = time.time()
    status, body = http_post_json("/api/v1/assessments/analyze", {
        "pcap_base64": imap_b64,
        "file_name": "imap_starttls.pcap",
        "title": "Live Stress Test - IMAP STARTTLS"
    })
    elapsed = time.time() - t0
    log(f"imap_starttls.pcap returned status {status} in {elapsed:.2f}s")
    if status not in (200, 201):
        raise RuntimeError(f"imap_starttls analysis failed: {status} -> {body}")
    log(f"Result: protocols={body.get('protocols_identified')}, posture_score={body.get('posture_score')}, grade={body.get('posture_grade')}")

    # 4. Sequential tests for key edge cases
    test_cases = [
        ("fixtures/pcap/smtp_starttls.pcap", 201, "SMTP STARTTLS"),
        ("fixtures/pcap/smtp_legacy.pcap", 201, "SMTP Legacy"),
        ("fixtures/pcap/pop3_stls.pcap", 201, "POP3 STLS"),
        ("fixtures/pcap_edge/smtp_downgrade_auth_exposed.pcap", 201, "SMTP Downgrade"),
        ("fixtures/pcap_edge/ipv6_smtp.pcap", 201, "IPv6 SMTP"),
        ("fixtures/pcap_edge/vlan_tagged_smtp.pcap", 201, "VLAN Tagged SMTP"),
        ("fixtures/pcap_edge/non_mail_http_on_port_25.pcap", 422, "Non-Mail HTTP rejection"),
        ("fixtures/pcap/empty.pcap", 422, "Empty PCAP (no email connections) rejection"),
        ("fixtures/pcap_edge/truncated_header.pcap", 400, "Truncated Header (<24 bytes) rejection"),
    ]

    for rel_path, expected_status, label in test_cases:
        p = find_fixture(rel_path)
        with open(p, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        t0 = time.time()
        st, res = http_post_json("/api/v1/assessments/analyze", {
            "pcap_base64": b64,
            "file_name": os.path.basename(p),
            "title": f"Stress - {label}"
        })
        dt = time.time() - t0
        log(f"[{label}] Status: {st} (expected {expected_status}) in {dt:.2f}s")
        assert st == expected_status, f"Expected {expected_status} for {label}, got {st}: {res}"

    # 5. Concurrent execution stress test
    log("Running concurrent stress test (5 parallel uploads)...")
    payloads = [
        ("smtp_starttls.pcap", find_fixture("fixtures/pcap/smtp_starttls.pcap")),
        ("imap_starttls.pcap", find_fixture("fixtures/pcap/imap_starttls.pcap")),
        ("pop3_stls.pcap", find_fixture("fixtures/pcap/pop3_stls.pcap")),
        ("smtp_downgrade.pcap", find_fixture("fixtures/pcap_edge/smtp_downgrade_auth_exposed.pcap")),
        ("ipv6_smtp.pcap", find_fixture("fixtures/pcap_edge/ipv6_smtp.pcap")),
    ]

    def upload_one(item):
        name, path = item
        with open(path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        t_start = time.time()
        s, r = http_post_json("/api/v1/assessments/analyze", {
            "pcap_base64": data,
            "file_name": name,
            "title": f"Concurrent {name}"
        })
        return name, s, time.time() - t_start, r

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(upload_one, payloads))
    total_time = time.time() - t0

    log(f"All 5 parallel uploads completed in {total_time:.2f}s:")
    for name, code, dur, _ in results:
        log(f"  - {name}: status={code} in {dur:.2f}s")
        assert code in (200, 201), f"Parallel upload {name} failed with {code}"

    log("ALL LIVE STRESS TESTS PASSED SUCCESSFULLY! The live Render instance is completely healthy and robust.")

if __name__ == "__main__":
    run_stress_test()
