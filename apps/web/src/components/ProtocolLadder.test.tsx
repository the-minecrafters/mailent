import { describe, expect, it } from "vitest";
import { emailSessionSchema } from "../api";
import { connectionStages } from "./ProtocolLadder";

const session = () => emailSessionSchema.parse({
  session_id: "s", sensor_id: "sensor", protocol: "smtp", provenance: { source: "capture", parser: "Zeek", parser_version: "8" },
  flow: { src_ip: "127.0.0.1", src_port: 1234, dst_ip: "127.0.0.1", dst_port: 465 },
  first_seen: "2020-01-01T00:00:00Z", last_seen: "2020-01-01T00:00:01Z",
  capture: { capture_sha256: "hash", connection_uid: "uid", normalizer_version: "1", source_logs: [], timeline: [], gaps: [] },
});
describe("connection evidence", () => {
  it("does not infer successful handshakes or plaintext from a port or missing evidence", () => {
    const stages = connectionStages(session());
    expect(stages.every(s => s.status === "unknown")).toBe(true);
    expect(stages.at(-1)?.detail).toContain("not confirmed");
  });
  it("does not turn a partial hello and TLS version into an established connection", () => {
    const s = session(); s.tls_version = "tls12";
    s.capture!.timeline.push({ kind: "tls_client_hello", timestamp: s.first_seen, source: "zeek" });
    expect(connectionStages(s).find(x => x.id === "handshake")?.detail).toContain("server response not confirmed");
    expect(connectionStages(s).at(-1)?.status).toBe("unknown");
    s.capture!.tls_established = true;
    expect(connectionStages(s).at(-1)?.status).toBe("observed");
  });
  it("evaluates certificate dates at capture time, not the current date", () => {
    const s = session();
    s.certificate = { reference: { subject: "CN=mail", issuer: "CN=ca", sha256_fingerprint: "hash" }, validity: { not_before: "2019-01-01T00:00:00Z", not_after: "2021-01-01T00:00:00Z" }, san: [] };
    expect(connectionStages(s).find(x => x.id === "certificate")?.status).toBe("observed");
    s.first_seen = "2022-01-01T00:00:00Z";
    expect(connectionStages(s).find(x => x.id === "certificate")?.status).toBe("warning");
  });
  it("shows a rejected upgrade without claiming encrypted transport", () => {
    const s = session(); s.starttls_state = "rejected";
    expect(connectionStages(s).find(x => x.id === "starttls")?.status).toBe("failed");
    expect(connectionStages(s).at(-1)?.status).toBe("unknown");
  });
});
