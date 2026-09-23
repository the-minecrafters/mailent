# Mailent · Project Showcase & Forensic Demonstration Guide

This guide provides real PCAP capture files, forensic workflow commands, and end-to-end steps to showcase Mailent to evaluators and judges (aligned with **SIH26159**).

---

## 1. Actual PCAP Capture Files

The repository includes real network captures extracted from Postfix and Dovecot mail servers in [`fixtures/pcap/`](file:///home/dipak/code/mailent/fixtures/pcap/):

| PCAP File | Protocol & Port | Cryptographic Scenarios & Findings Demonstrated |
| :--- | :--- | :--- |
| **`smtp_legacy.pcap`** | SMTP (Port 25) | • Legacy TLSv1.0 negotiation (`TLS_LEGACY_VERSION`)<br>• Weak CBC cipher `TLS_RSA_WITH_AES_128_CBC_SHA` (`TLS_WEAK_CIPHER`)<br>• Static RSA key exchange without Forward Secrecy (`TLS_NO_FORWARD_SECRECY`)<br>• Expired X.509 certificate (`CERT_EXPIRED`) |
| **`smtp_starttls.pcap`** | SMTP (Port 25) | • Plaintext greeting & `EHLO` command extraction<br>• Explicit `STARTTLS` negotiation and server `220` response<br>• In-flight upgrade to TLS session with complete TCP stream reconstruction |
| **`smtp_starttls.pcapng`**| SMTP (Port 25) | • PCAPNG format parsing and dual-block encapsulation validation |
| **`imap_starttls.pcap`** | IMAP (Port 143) | • Passive detection of `. STARTTLS` command on standard IMAP port<br>• TLS handshake state machine transition |
| **`imap_tls13.pcap`** | IMAPS (Port 993) | • Modern TLS 1.3 direct TLS session<br>• AEAD cipher `TLS_AES_256_GCM_SHA384` & ephemeral ECDHE key exchange |
| **`pop3_stls.pcap`** | POP3 (Port 110) | • POP3 protocol identification and `STLS` command upgrade |

---

## 2. Terminal Demonstration: Sensor CLI

You can execute the passive capture analysis directly via the command line without opening a browser.

### A. Analyze Weak/Legacy SMTP Capture
```bash
# Analyze smtp_legacy.pcap and output structured forensic JSON
./target/debug/mailent-sensor analyze fixtures/pcap/smtp_legacy.pcap --json
```

**Key forensic outputs visible in the terminal**:
- `capture_sha256`: SHA-256 evidentiary hash of the capture file
- `protocol`: `"smtp"`
- `starttls_state`: `"tls_established"`
- `tls_version`: `"TLSv1.0"`
- `cipher_suite`: `{"id": 47, "name": "TLS_RSA_WITH_AES_128_CBC_SHA"}`
- `key_exchange`: `"rsa_static"`
- `certificate`: Subject, Issuer, Validity timestamps, and SANs
- `timeline`: Sequence of packet events from `tcp_connected` to `starttls_accepted` and `tls_established`

### B. Analyze Modern IMAP TLS 1.3 Capture
```bash
# Analyze IMAP TLS 1.3 capture
./target/debug/mailent-sensor analyze fixtures/pcap/imap_tls13.pcap --json
```

---

## 3. API Demonstration: HTTP / REST Workflow

You can run these commands against the local core server or the live production deployment at `https://mailent.onrender.com`.

### A. Analyze PCAP via REST API (Guest / Non-Persistent Mode)
Upload a base64-encoded PCAP file using the guest header `X-Mailent-Guest: true`:

```bash
# 1. Base64 encode the PCAP
PCAP_B64=$(base64 -w 0 fixtures/pcap/smtp_legacy.pcap)

# 2. Submit capture for passive forensic analysis
curl -s -X POST https://mailent.onrender.com/api/v1/assessments/analyze \
  -H "Content-Type: application/json" \
  -H "X-Mailent-Guest: true" \
  -d "{\"file_name\": \"smtp_legacy.pcap\", \"title\": \"Forensic Audit - Legacy Mail Server\", \"pcap_base64\": \"$PCAP_B64\"}" | jq .
```

### B. Query Assessment Results & Posture Score
```bash
# List all assessments
curl -s -H "X-Mailent-Guest: true" https://mailent.onrender.com/api/v1/assessments | jq .
```

### C. Authenticated Mode (Persistent PostgreSQL Storage)
To persist assessments, sessions, and findings across server restarts, authenticate with the approved workspace account:

```bash
# 1. Obtain JWT token for approved workspace member
TOKEN=$(curl -s -X POST "https://vuskxbttfmmyxpqudjwv.supabase.co/auth/v1/token?grant_type=password" \
  -H "apikey: sb_publishable_JlhOKBZix9ohRNUSW87Qrw_qAt93seo" \
  -H "Content-Type: application/json" \
  -d '{"email":"seadeepie@gmail.com","password":"Mailent2026!"}' | jq -r .access_token)

# 2. Perform authenticated analysis (persisted to Supabase PostgreSQL in Singapore)
curl -s -X POST https://mailent.onrender.com/api/v1/assessments/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"file_name\": \"smtp_legacy.pcap\", \"title\": \"Persistent Audit - Production Gateway\", \"pcap_base64\": \"$PCAP_B64\"}" | jq .
```

---

## 4. Web UI Showcase Walkthrough

### Option 1: Live Hosted Platform
Open **`https://mailent.onrender.com`** in any browser.

1. **Editorial Landing Page (`/`)**:
   - Technical editorial design with serif typography and problem statement overview.
   - Click **"Open your workspace"** to enter `/workspace/overview`.

2. **Authentication Gate**:
   - **Skip Sign-In (Guest / Ephemeral Mode)**: Click **"Skip sign in (use without persistence)"** at the bottom of the card. You can immediately analyze PCAPs in-memory without creating an account.
   - **Persistent Sign-In**: Enter `seadeepie@gmail.com` with password `Mailent2026!` to access persistent cloud storage.

3. **Analyze Capture Workflow**:
   - Click the **"+ Analyze capture"** button in the top right.
   - Choose [`fixtures/pcap/smtp_legacy.pcap`](file:///home/dipak/code/mailent/fixtures/pcap/smtp_legacy.pcap).
   - Click **"Analyze capture"**.
   - Inspect the reconstructed findings:
     - **TLS 1.0 Legacy Protocol**: Warning with remediation instructions.
     - **Static RSA Key Exchange**: Non-forward-secret cipher warning.
     - **Expired X.509 Certificate**: Validity period expired.
   - Click **"Export JSON"** to download the complete forensic dossier with SHA-256 hash.

4. **Forensic Evidence Inspection**:
   - Switch between **Sessions**, **Findings**, **Mail servers**, and **Collectors** tabs in the sidebar to review protocol timelines and certificate chains.
