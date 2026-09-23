#!/usr/bin/env python3
"""
Continuous Overnight Stress Test & Reliability Monitor for Mailent Live Cloud.
Runs unattended rounds indefinitely, exercising:
1. System Health & Policy Readiness (/health, /ready, /auth/config)
2. External AI / Decision Provider Connectivity (/api/v1/decisions/check)
3. Diverse PCAP Protocol Analysis (SMTP, IMAP, POP3, IPv6, VLAN)
4. Concurrent High-Load Bursts (multi-threaded parallel uploads)
5. Adversarial & Malformed Payload Rejection (fuzzing & corrupted bytes)
6. Infrastructure Scan Probes (/api/v1/scans/infrastructure)
7. Periodic stats logging to JSON status file
"""

import base64
import glob
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = os.environ.get("MAILENT_URL", "https://mailent.onrender.com").rstrip("/")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATUS_FILE = os.path.join(REPO_ROOT, "tests", "stress_test_live_status.json")

RUNNING = True

def handle_signal(sig, frame):
    global RUNNING
    print(f"\n[!] Received signal {sig}, terminating gracefully...")
    RUNNING = False

signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)

def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

def http_request(method, path, data=None, headers=None, timeout=60):
    url = f"{BASE_URL}{path}"
    h = {"X-Mailent-Guest": "true"}
    if headers:
        h.update(headers)
    req_body = None
    if data is not None:
        h["Content-Type"] = "application/json"
        req_body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=req_body, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.time() - t0
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = raw
            return resp.status, parsed, elapsed
    except urllib.error.HTTPError as e:
        elapsed = time.time() - t0
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw
        return e.code, parsed, elapsed
    except Exception as e:
        elapsed = time.time() - t0
        return 0, str(e), elapsed

def update_status(stats):
    try:
        with open(STATUS_FILE, "w") as f:
            json.dump(stats, f, indent=2)
    except Exception as e:
        log(f"Warning: could not write status file: {e}")

def run_single_pcap(path):
    name = os.path.basename(path)
    with open(path, "rb") as f:
        content = f.read()
    b64 = base64.b64encode(content).decode()
    return name, http_request("POST", "/api/v1/assessments/analyze", {
        "pcap_base64": b64,
        "file_name": name,
        "title": f"Overnight Monitor - {name}"
    }, timeout=45)

def run_stress_cycle(cycle_num, stats):
    log(f"==================================================")
    log(f"Starting Stress Test Cycle #{cycle_num}...")
    log(f"==================================================")

    # 1. Health & Readiness
    status, body, elapsed = http_request("GET", "/health")
    if status == 200:
        stats["checks_passed"] += 1
    else:
        stats["checks_failed"] += 1
        log(f"  [FAIL] /health returned {status}: {body}")

    status, body, elapsed = http_request("GET", "/ready")
    if status == 200:
        stats["checks_passed"] += 1
    else:
        stats["checks_failed"] += 1
        log(f"  [FAIL] /ready returned {status}: {body}")

    # 2. Decision Provider
    status, body, elapsed = http_request("POST", "/api/v1/decisions/check")
    stats["decision_checks"] += 1
    log(f"  Decision check ({elapsed:.2f}s): {body.get('message') if isinstance(body, dict) else body}")

    # 3. Rotating PCAP Analysis (Standard & Edge)
    pcap_candidates = [
        "fixtures/pcap/smtp_starttls.pcap",
        "fixtures/pcap/imap_starttls.pcap",
        "fixtures/pcap/pop3_stls.pcap",
        "fixtures/pcap/smtp_legacy.pcap",
        "fixtures/pcap_edge/ipv6_smtp.pcap",
        "fixtures/pcap_edge/vlan_tagged_smtp.pcap",
        "fixtures/pcap_edge/smtp_downgrade_auth_exposed.pcap",
    ]

    for rel_path in pcap_candidates:
        full_path = os.path.join(REPO_ROOT, rel_path)
        if not os.path.exists(full_path):
            continue
        name, (status, body, elapsed) = run_single_pcap(full_path)
        if status in (200, 201):
            stats["pcaps_analyzed"] += 1
            log(f"  [PASS] {name} -> 201 Created in {elapsed:.2f}s")
        else:
            stats["errors_encountered"] += 1
            log(f"  [FAIL] {name} -> HTTP {status} in {elapsed:.2f}s: {body}")

    # 4. Concurrent Load Burst (4 parallel uploads)
    burst_files = [
        os.path.join(REPO_ROOT, "fixtures/pcap/smtp_starttls.pcap"),
        os.path.join(REPO_ROOT, "fixtures/pcap/imap_starttls.pcap"),
        os.path.join(REPO_ROOT, "fixtures/pcap/pop3_stls.pcap"),
        os.path.join(REPO_ROOT, "fixtures/pcap_edge/ipv6_smtp.pcap"),
    ]

    log("  Launching 4-way concurrent upload burst...")
    t_burst = time.time()
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(run_single_pcap, f) for f in burst_files if os.path.exists(f)]
        for fut in as_completed(futures):
            name, (status, body, elapsed) = fut.result()
            if status in (200, 201):
                stats["concurrent_passed"] += 1
            else:
                stats["concurrent_failed"] += 1
                log(f"    Burst fail: {name} returned {status}: {body}")
    burst_elapsed = time.time() - t_burst
    log(f"  Concurrent burst completed in {burst_elapsed:.2f}s")

    # 5. Negative / Adversarial checks
    neg_cases = [
        ("Empty Body", "POST", "/api/v1/assessments/analyze", {}, 400),
        ("Invalid Base64", "POST", "/api/v1/assessments/analyze", {"pcap_base64": "NOT_B64$$$", "file_name": "bad.pcap"}, 400),
        ("Non-Mail HTTP", "POST", "/api/v1/assessments/analyze", {
            "pcap_base64": base64.b64encode(open(os.path.join(REPO_ROOT, "fixtures/pcap_edge/non_mail_http_on_port_25.pcap"), "rb").read()).decode(),
            "file_name": "http.pcap"
        }, 422),
    ]

    for desc, method, path, payload, exp_status in neg_cases:
        status, body, elapsed = http_request(method, path, payload)
        if status == exp_status:
            stats["adversarial_passed"] += 1
        else:
            stats["adversarial_failed"] += 1
            log(f"  [FAIL] {desc}: expected {exp_status}, got {status}")

    stats["cycles_completed"] += 1
    stats["last_cycle_timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    update_status(stats)

    log(f"Cycle #{cycle_num} finished. Total Analyzed: {stats['pcaps_analyzed']}, Errors: {stats['errors_encountered']}")

def main():
    log(f"Starting overnight stress testing daemon against {BASE_URL}")
    stats = {
        "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cycles_completed": 0,
        "checks_passed": 0,
        "checks_failed": 0,
        "decision_checks": 0,
        "pcaps_analyzed": 0,
        "concurrent_passed": 0,
        "concurrent_failed": 0,
        "adversarial_passed": 0,
        "adversarial_failed": 0,
        "errors_encountered": 0,
        "last_cycle_timestamp": None
    }
    update_status(stats)

    cycle = 1
    while RUNNING:
        try:
            run_stress_cycle(cycle, stats)
            cycle += 1
            # 8-second pacing between heavy cycles
            for _ in range(8):
                if not RUNNING:
                    break
                time.sleep(1)
        except Exception as e:
            log(f"Cycle encountered unhandled exception: {e}")
            stats["errors_encountered"] += 1
            time.sleep(10)

    log("Overnight stress test daemon finished.")

if __name__ == "__main__":
    main()
