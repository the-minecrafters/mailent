// Older saved records retain their original text for exports and audit history.
// Present known generated labels consistently with the current workspace.
export function workspaceName(org?: { id: string; name: string }): string {
  if (
    !org ||
    (org.id === "00000000-0000-0000-0000-000000000001" &&
      org.name === "Acme Inc")
  ) {
    return "Workspace";
  }
  return org.name;
}

const summaries: Record<string, string> = {
  "Critical cryptographic non-compliances detected (deprecated protocol version, weak cipher or expired certificate) that expose mail transport to downgrade and interception.":
    "Critical issues were found in this traffic. Review the findings and recommended fixes.",
  "High severity cryptographic non-compliance identified; requires prompt configuration remediation to prevent transport vulnerabilities.":
    "High-priority issues were found. Review the affected connections and update the server settings.",
  "Evaluated email transport complies with modern cryptographic baseline; no policy violations observed in analyzed traffic.":
    "No policy issues were found in the available traffic.",
  "Moderate security observations detected; review recommendations to align with modern cryptographic best practices.":
    "Some settings need attention. Review the findings for recommended changes.",
};

export function assessmentSummary(value: string): string {
  return Object.hasOwn(summaries, value) ? summaries[value] : value;
}

export function connectionSource(value: string): string {
  if (value === "Active network probe" || value === "mailent-probe")
    return "Live connection check";
  return value.replace(/^Zeek (.+) analyzer \/ (.+) engine$/, "Zeek $1 · $2");
}

export function reviewTitle(value: string): string {
  return value
    .replace(/^Security Incident: /, "Review: ")
    .replace(/^Anomalous Activity: /, "Unusual activity: ")
    .replace(/^Configuration Drift: /, "Settings changed: ");
}

export function reviewSummary(value: string): string {
  return value.replace(
    /^Correlated incident involving (\d+) findings, (\d+) drifts, and (\d+) anomaly signals\.$/,
    "$1 findings, $2 settings changes, and $3 unusual changes to review.",
  );
}

export function domainFromTitle(title: string): string {
  return title
    .replace(/ (Infrastructure Assessment|Domain check)$/i, "")
    .trim();
}

export function liveCheckMessage(value: string): string {
  const messages: Record<string, string> = {
    "Probe does not identify the original affected endpoint":
      "The check does not match the original mail server connection.",
    "Probe failed or is incomplete; no fix established":
      "The check failed or is incomplete. The fix has not been verified.",
    "Probe reached a different address; original affected endpoint remains unverified":
      "The check reached a different address. The original connection has not been verified.",
    "Active probe observed a different certificate than the passively captured session":
      "The live check found a different certificate from the captured connection.",
    "Certificate issuer differs between passive observation and active probe":
      "The certificate issuer differs between the captured connection and the live check.",
  };
  if (Object.hasOwn(messages, value)) return messages[value];
  return value.replace(
    /^Passive observation saw (.+); active probe negotiated (.+)$/,
    "The captured connection used $1; the live check used $2",
  );
}

export function reportTitle(value: string): string {
  return value
    .replace(/^Forensic report/i, "Security report")
    .replace(/ Mail Infrastructure Forensic Report$/, " Mail security report");
}
