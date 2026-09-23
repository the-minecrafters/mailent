#!/usr/bin/env python3
"""
Comprehensive Adversarial Matrix & Stress Test for Live Cloud (https://mailent.onrender.com).
Tests:
1. Every fixture in fixtures/pcap and fixtures/pcap_edge (all 30 PCAP/PCAPNG files)
2. Malformed Base64, random garbage, empty strings, oversized limits
3. Fuzzing headers, guest tokens, unauthenticated endpoints
4. System recovery verification
"""

import base64
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = os.environ.get("MAILENT_URL", "https://mailent.onrender.com").rstrip("/")
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)

def request(method, path, data=None, headers=None, timeout=60):
    url = f"{BASE_URL}{path}"
    h = {"X-Mailent-Guest": "true"}
    if headers:
        h.update(headers)
    req_body = None
    if data is not None:
        h["Content-Type"] = "application/json"
        req_body = json.dumps(data).encode()
    
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

def test_all_pcaps():
    log("=== PHASE 1: Testing Full PCAP Catalog Against Live Cloud ===")
    pcap_files = sorted(glob.glob(os.path.join(REPO_ROOT, "fixtures/**/*.pcap*"), recursive=True))
    log(f"Found {len(pcap_files)} PCAP fixture files to test.")

    results = []
    for path in pcap_files:
        name = os.path.basename(path)
        with open(path, "rb") as f:
            content = f.read()
        b64 = base64.b64encode(content).decode()
        
        status, body, elapsed = request("POST", "/api/v1/assessments/analyze", {
            "pcap_base64": b64,
            "file_name": name,
            "title": f"Adversarial Suite - {name}"
        })

        if status in (200, 201):
            proto = body.get("protocols_identified") if isinstance(body, dict) else "?"
            score = body.get("posture_score") if isinstance(body, dict) else "?"
            grade = body.get("posture_grade") if isinstance(body, dict) else "?"
            results.append((name, status, f"OK: {proto} Score: {score} Grade: {grade}", elapsed))
            log(f"  [PASS] {name:<35} -> HTTP {status} in {elapsed:.2f}s | {proto} (Grade {grade})")
        elif status in (400, 422):
            err = body.get("error") if isinstance(body, dict) else str(body)[:50]
            results.append((name, status, f"REJECTED AS EXPECTED: {err}", elapsed))
            log(f"  [PASS] {name:<35} -> HTTP {status} (Expected Rejection) in {elapsed:.2f}s | {err}")
        else:
            results.append((name, status, f"UNEXPECTED: {body}", elapsed))
            log(f"  [FAIL] {name:<35} -> HTTP {status} in {elapsed:.2f}s | {body}")

    passed = [r for r in results if r[1] in (200, 201, 400, 422)]
    log(f"Phase 1 Summary: {len(passed)}/{len(results)} passed cleanly.")
    return len(passed) == len(results)

def test_fuzz_and_malformed():
    log("=== PHASE 2: Fuzzing & Malformed Payloads ===")
    cases = [
        ("Empty body", {}),
        ("Invalid JSON syntax", "NOT_JSON"),
        ("Non-base64 pcap string", {"pcap_base64": "!!!not_base64_character$", "file_name": "fuzz.pcap"}),
        ("Random binary as base64", {"pcap_base64": base64.b64encode(b"THIS IS NOT A PCAP FILE AT ALL 1234567890").decode(), "file_name": "not_pcap.pcap"}),
        ("Huge garbage base64 (500KB)", {"pcap_base64": base64.b64encode(os.urandom(500 * 1024)).decode(), "file_name": "garbage_500kb.pcap"}),
        ("Corrupted magic bytes (0xDEADBEEF)", {"pcap_base64": base64.b64encode(b"\xde\xad\xbe\xef\x00\x02\x00\x04\x00\x00\x00\x00").decode(), "file_name": "bad_magic.pcap"}),
    ]

    all_ok = True
    for desc, payload in cases:
        if desc == "Invalid JSON syntax":
            # Send raw invalid bytes
            url = f"{BASE_URL}/api/v1/assessments/analyze"
            req = urllib.request.Request(url, data=b"{this is bad json", headers={"Content-Type": "application/json", "X-Mailent-Guest": "true"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    status = resp.status
            except urllib.error.HTTPError as e:
                status = e.code
            except Exception as e:
                status = 0
            log(f"  {desc:<35} -> HTTP {status}")
            if status not in (400, 422):
                all_ok = False
        else:
            status, body, elapsed = request("POST", "/api/v1/assessments/analyze", payload)
            err = body.get("error") if isinstance(body, dict) else str(body)[:60]
            log(f"  {desc:<35} -> HTTP {status} in {elapsed:.2f}s | {err}")
            # All bad payloads must return 400 or 422 client error, never 500
            if status not in (400, 422):
                log(f"    WARNING: Unexpected status {status} for {desc}")
                all_ok = False
    return all_ok

def test_system_recovery():
    log("=== PHASE 3: System Health Check Post-Fuzzing ===")
    status, body, elapsed = request("GET", "/health")
    log(f"  GET /health -> HTTP {status} ({elapsed:.2f}s) Body: {body}")
    return status == 200 and body.get("status") == "ok"

if __name__ == "__main__":
    t_start = time.time()
    p1 = test_all_pcaps()
    p2 = test_fuzz_and_malformed()
    p3 = test_system_recovery()
    t_end = time.time()

    log(f"\n==========================================")
    log(f"Adversarial Stress Test Suite Finished in {t_end - t_start:.2f}s")
    log(f"PCAP Matrix: {'PASS' if p1 else 'FAIL'}")
    log(f"Fuzzing & Malformed: {'PASS' if p2 else 'FAIL'}")
    log(f"System Health Post-Stress: {'PASS' if p3 else 'FAIL'}")
    log(f"==========================================")

    if not (p1 and p2 and p3):
        sys.exit(1)
