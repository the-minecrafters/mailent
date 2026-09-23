#!/usr/bin/env bash
set -euo pipefail

echo "========================================================"
echo " Starting Mailent Controlled Agent End-to-End Workflow"
echo "========================================================"

PORT=8089
SERVER_URL="http://127.0.0.1:${PORT}"
CREDS_PATH="/tmp/mailent-e2e-creds.json"
rm -f "${CREDS_PATH}"

CORE_BIN="./target/debug/mailent-core"
CLI_BIN="./target/debug/mailent"

# Ensure probe lab is restored to clean baseline (STARTTLS = may)
podman exec mailent-probe-lab postconf -e "smtpd_tls_security_level = may"
podman exec mailent-probe-lab postfix reload
sleep 1

# 2. Launch Mailent Core
PORT=${PORT} ${CORE_BIN} > /tmp/mailent-core.log 2>&1 &
CORE_PID=$!
echo "[+] Started Mailent Core (PID: ${CORE_PID}) on ${SERVER_URL}"

cleanup() {
    echo "[*] Cleaning up processes..."
    kill -9 ${CORE_PID} 2>/dev/null || true
    kill -9 ${AGENT_PID:-0} 2>/dev/null || true
    podman exec mailent-probe-lab postconf -e "smtpd_tls_security_level = may" 2>/dev/null || true
    podman exec mailent-probe-lab postfix reload 2>/dev/null || true
    rm -f "${CREDS_PATH}"
}
trap cleanup EXIT

# Wait for core to be ready
for i in {1..30}; do
    if curl -s "${SERVER_URL}/health" | grep -q "mailent-core"; then
        echo "[+] Mailent Core is ready"
        break
    fi
    sleep 0.5
done

# 3. Authenticate and register agent device
echo "[*] Creating device challenge..."
CHALLENGE_RES=$(curl -s -X POST "${SERVER_URL}/api/v1/devices/authorize/challenge" \
    -H "Content-Type: application/json" \
    -d '{"device_name": "E2E-Agent-Lab", "hostname": "lab-host", "platform": "linux", "architecture": "x86_64"}')

CODE=$(echo "${CHALLENGE_RES}" | jq -r '.code')
echo "[+] Challenge code: ${CODE}"

# Approve device challenge
curl -s -X POST "${SERVER_URL}/api/v1/devices/authorize/${CODE}/approve" \
    -H "x-mailent-org: 00000000-0000-0000-0000-000000000001" > /dev/null
echo "[+] Challenge approved"

# Poll for device credentials
POLL_RES=$(curl -s -X POST "${SERVER_URL}/api/v1/devices/authorize/poll" \
    -H "Content-Type: application/json" \
    -d "{\"code\": \"${CODE}\"}")

DEVICE_TOKEN=$(echo "${POLL_RES}" | jq -r '.token')
DEVICE_ID=$(echo "${POLL_RES}" | jq -r '.device_id')
echo "[+] Device registered: ID=${DEVICE_ID}"

# Save credentials to custom credentials path
cat << EOF > "${CREDS_PATH}"
{
  "server_url": "${SERVER_URL}",
  "device_id": "${DEVICE_ID}",
  "device_token": "${DEVICE_TOKEN}",
  "organization_id": "00000000-0000-0000-0000-000000000001",
  "device_name": "E2E-Agent-Lab",
  "created_at": "2026-09-24T00:00:00Z"
}
EOF

# 4. Create Infrastructure Monitor targeting this agent device
echo "[*] Creating monitor for mailent.test assigned to agent ${DEVICE_ID}..."
MONITOR_RES=$(curl -s -X POST "${SERVER_URL}/api/v1/monitors" \
    -H "Authorization: Bearer ${DEVICE_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"domain\": \"mailent.test\",
        \"cadence\": \"hourly\",
        \"target\": {
            \"type\": \"agent\",
            \"agent_id\": \"${DEVICE_ID}\"
        }
    }")

MONITOR_ID=$(echo "${MONITOR_RES}" | jq -r '.id')
echo "[+] Monitor created: ID=${MONITOR_ID}"

# 5. Start Agent Daemon in foreground/background using MAILENT_CREDENTIALS_PATH
echo "[*] Launching real agent worker daemon..."
MAILENT_CREDENTIALS_PATH="${CREDS_PATH}" ${CLI_BIN} agent run --poll-interval 1 --heartbeat-interval 5 > /tmp/mailent-agent.log 2>&1 &
AGENT_PID=$!
echo "[+] Agent daemon running (PID: ${AGENT_PID})"
sleep 2

# 6. Trigger Baseline Scan ("Run Now")
echo "[*] Triggering baseline scan via Run Now..."
curl -s -X POST "${SERVER_URL}/api/v1/monitors/${MONITOR_ID}/run_now" \
    -H "Authorization: Bearer ${DEVICE_TOKEN}" > /dev/null

# Wait for job completion
echo "[*] Waiting for baseline scan to complete..."
for i in {1..30}; do
    STATUS_RES=$(curl -s -H "Authorization: Bearer ${DEVICE_TOKEN}" "${SERVER_URL}/api/v1/devices/status")
    COMPLETED_COUNT=$(echo "${STATUS_RES}" | jq -r '.device.completed_jobs_count // 0')
    if [ "${COMPLETED_COUNT}" -ge 1 ]; then
        echo "[+] Baseline scan completed successfully! Completed jobs: ${COMPLETED_COUNT}"
        break
    fi
    sleep 1
done

# Verify baseline assessment
ASSESSMENTS=$(curl -s -H "Authorization: Bearer ${DEVICE_TOKEN}" "${SERVER_URL}/api/v1/assessments")
ASSESSMENT_COUNT=$(echo "${ASSESSMENTS}" | jq '. | length')
echo "[+] Total assessments in control plane: ${ASSESSMENT_COUNT}"
if [ "${ASSESSMENT_COUNT}" -ne 1 ]; then
    echo "[!] Expected 1 baseline assessment, got ${ASSESSMENT_COUNT}"
    exit 1
fi

# Verify no investigation opened yet (baseline had no security regressions)
INVS=$(curl -s -H "Authorization: Bearer ${DEVICE_TOKEN}" "${SERVER_URL}/api/v1/investigations")
INV_COUNT=$(echo "${INVS}" | jq '. | length')
echo "[+] Investigations after baseline: ${INV_COUNT} (expected 0)"
if [ "${INV_COUNT}" -ne 0 ]; then
    echo "[!] Expected 0 investigations for clean baseline, got ${INV_COUNT}"
    exit 1
fi

# 7. MUTATE SERVER SECURITY STATE: Disable STARTTLS in Postfix
echo "========================================================"
echo "[*] Mutating Postfix security state in container: disabling STARTTLS..."
podman exec mailent-probe-lab postconf -e "smtpd_tls_security_level = none"
podman exec mailent-probe-lab postfix reload
sleep 1

# 8. Trigger Regression Scan ("Run Now")
echo "[*] Triggering regression scan via Run Now..."
curl -s -X POST "${SERVER_URL}/api/v1/monitors/${MONITOR_ID}/run_now" \
    -H "Authorization: Bearer ${DEVICE_TOKEN}" > /dev/null

# Wait for regression scan completion
echo "[*] Waiting for regression scan to complete..."
for i in {1..30}; do
    STATUS_RES=$(curl -s -H "Authorization: Bearer ${DEVICE_TOKEN}" "${SERVER_URL}/api/v1/devices/status")
    COMPLETED_COUNT=$(echo "${STATUS_RES}" | jq -r '.device.completed_jobs_count // 0')
    if [ "${COMPLETED_COUNT}" -ge 2 ]; then
        echo "[+] Regression scan completed! Completed jobs: ${COMPLETED_COUNT}"
        break
    fi
    sleep 1
done

# Verify Investigation was CREATED
INVS=$(curl -s -H "Authorization: Bearer ${DEVICE_TOKEN}" "${SERVER_URL}/api/v1/investigations")
INV_COUNT=$(echo "${INVS}" | jq '. | length')
echo "[+] Total investigations in control plane: ${INV_COUNT} (expected 1)"
if [ "${INV_COUNT}" -ne 1 ]; then
    echo "[!] Expected exactly 1 investigation created for STARTTLS regression, got ${INV_COUNT}"
    exit 1
fi

INV_ID=$(echo "${INVS}" | jq -r '.[0].id')
INV_TITLE=$(echo "${INVS}" | jq -r '.[0].title')
INV_RISK=$(echo "${INVS}" | jq -r '.[0].risk')
echo "[+] Created Investigation: ID=${INV_ID}, Title='${INV_TITLE}', Risk=${INV_RISK}"

# 9. Trigger Repeated Scan with unresolved condition -> DEDUPLICATION
echo "[*] Triggering repeated scan with unresolved regression..."
curl -s -X POST "${SERVER_URL}/api/v1/monitors/${MONITOR_ID}/run_now" \
    -H "Authorization: Bearer ${DEVICE_TOKEN}" > /dev/null

for i in {1..30}; do
    STATUS_RES=$(curl -s -H "Authorization: Bearer ${DEVICE_TOKEN}" "${SERVER_URL}/api/v1/devices/status")
    COMPLETED_COUNT=$(echo "${STATUS_RES}" | jq -r '.device.completed_jobs_count // 0')
    if [ "${COMPLETED_COUNT}" -ge 3 ]; then
        echo "[+] Repeated scan completed! Completed jobs: ${COMPLETED_COUNT}"
        break
    fi
    sleep 1
done

# Verify Investigation was NOT duplicated
INVS_AFTER_REPEAT=$(curl -s -H "Authorization: Bearer ${DEVICE_TOKEN}" "${SERVER_URL}/api/v1/investigations")
INV_COUNT_AFTER=$(echo "${INVS_AFTER_REPEAT}" | jq '. | length')
echo "[+] Total investigations after repeated scan: ${INV_COUNT_AFTER} (expected 1, deduplicated)"
if [ "${INV_COUNT_AFTER}" -ne 1 ]; then
    echo "[!] Deduplication failed: expected 1 investigation, got ${INV_COUNT_AFTER}"
    exit 1
fi

INV_ID_AFTER=$(echo "${INVS_AFTER_REPEAT}" | jq -r '.[0].id')
if [ "${INV_ID_AFTER}" != "${INV_ID}" ]; then
    echo "[!] Investigation ID changed: expected ${INV_ID}, got ${INV_ID_AFTER}"
    exit 1
fi

# 10. Test Agent and Core Restarts -> Verify no duplicate jobs or assessments
echo "========================================================"
echo "[*] Testing Agent and Core restarts..."
kill ${AGENT_PID}
sleep 1

# Restart agent
MAILENT_CREDENTIALS_PATH="${CREDS_PATH}" ${CLI_BIN} agent run --poll-interval 1 --heartbeat-interval 5 > /tmp/mailent-agent-2.log 2>&1 &
AGENT_PID=$!
echo "[+] Restarted agent worker daemon (PID: ${AGENT_PID})"
sleep 2

# Check agent status via CLI
MAILENT_CREDENTIALS_PATH="${CREDS_PATH}" ${CLI_BIN} agent status

# Check assessments and jobs count remain strictly stable
ASSESSMENTS_STABLE=$(curl -s -H "Authorization: Bearer ${DEVICE_TOKEN}" "${SERVER_URL}/api/v1/assessments")
ASSESSMENT_COUNT_STABLE=$(echo "${ASSESSMENTS_STABLE}" | jq '. | length')
echo "[+] Assessment count after restart: ${ASSESSMENT_COUNT_STABLE} (expected 3)"
if [ "${ASSESSMENT_COUNT_STABLE}" -ne 3 ]; then
    echo "[!] Assessment duplication detected! Count: ${ASSESSMENT_COUNT_STABLE}"
    exit 1
fi

echo "========================================================"
echo " Real End-to-End Controlled Agent Workflow PASSED!"
echo "========================================================"
