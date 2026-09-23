import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import modern from "../../../fixtures/synthetic/smtp_tls13_healthy.json";
import { App } from "./App";

const ready = {
  ready: true,
  policy_loaded: true,
  policy_name: "modern",
  policy_version: "1.0.0",
  rule_count: 3,
  storage: "in_memory",
  decision_provider: "disabled",
};
function setup(
  fetcher: ReturnType<typeof vi.fn>,
  initialView:
    | "assets"
    | "sessions"
    | "findings"
    | "sensors"
    | "evaluator" = "evaluator",
) {
  vi.stubGlobal("fetch", fetcher);
  render(
    <QueryClientProvider
      client={
        new QueryClient({ defaultOptions: { queries: { retry: false } } })
      }
    >
      <App initialView={initialView} />
    </QueryClientProvider>,
  );
  return userEvent.setup();
}
function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status });
}

describe("observation console", () => {
  it("shows pending readiness without invented findings", () => {
    setup(vi.fn(() => new Promise(() => {})));
    expect(screen.getByRole("status")).toHaveTextContent("Connecting");
    expect(
      screen.getByRole("button", { name: "Evaluate observation" }),
    ).toBeDisabled();
    expect(screen.getByText("No observation evaluated")).toBeVisible();
  });
  it("reports an unavailable core and disables evaluation", async () => {
    setup(vi.fn().mockRejectedValue(new Error("Connection refused")));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Cannot connect to Mailent",
    );
    expect(
      screen.getByRole("button", { name: "Evaluate observation" }),
    ).toBeDisabled();
  });
  it("renders a real response shape, clears stale results when input changes", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(response(ready))
      .mockResolvedValueOnce(
        response({
          session_id: modern.observation_id,
          observation: modern,
          candidate_count: 0,
          findings: [],
        }),
      );
    const user = setup(fetcher);
    await screen.findByText("Connected");
    await user.selectOptions(
      screen.getByLabelText("Synthetic fixture"),
      "modern",
    );
    await user.click(
      screen.getByRole("button", { name: "Evaluate observation" }),
    );
    expect(
      await screen.findByText("No violations found by the evaluated rules"),
    ).toBeVisible();
    expect(fetcher).toHaveBeenLastCalledWith(
      "/api/v1/observations/evaluate",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(modern, null, 2),
      }),
    );
    await user.selectOptions(
      screen.getByLabelText("Synthetic fixture"),
      "legacy",
    );
    expect(
      screen.queryByText("No violations found by the evaluated rules"),
    ).not.toBeInTheDocument();
  });
  it("shows pending evaluation and server rejection without stale results", async () => {
    let resolveEvaluation: (value: Response) => void = () => {};
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(response(ready))
      .mockImplementationOnce(
        () =>
          new Promise<Response>((resolve) => {
            resolveEvaluation = resolve;
          }),
      );
    const user = setup(fetcher);
    await screen.findByText("Connected");
    await user.click(
      screen.getByRole("button", { name: "Evaluate observation" }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Evaluating observation",
    );
    resolveEvaluation(new Response("invalid observation", { status: 422 }));
    expect(await screen.findByRole("alert")).toHaveTextContent("422");
  });
  it("rejects invalid JSON locally and malformed API responses visibly", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(response(ready))
      .mockResolvedValueOnce(response({ findings: "bad contract" }));
    const user = setup(fetcher);
    await screen.findByText("Connected");
    await user.clear(screen.getByLabelText("Normalized observation JSON"));
    await user.click(
      screen.getByRole("button", { name: "Evaluate observation" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Evaluation failed",
    );
    expect(fetcher).toHaveBeenCalledTimes(1);
    await user.selectOptions(
      screen.getByLabelText("Synthetic fixture"),
      "modern",
    );
    await user.click(
      screen.getByRole("button", { name: "Evaluate observation" }),
    );
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Evaluation failed",
    );
  });

  it("renders analyzed sessions table and inspects session timeline", async () => {
    const mockSession = {
      session_id: "3779da6e-6324-5aca-84b5-06cde5297384",
      sensor_id: "sensor-local-01",
      protocol: "smtp",
      client: "127.0.0.1:41580",
      server: "127.0.0.1:25",
      starttls_state: "tls_established",
      tls_version: "TLSv1.2",
      cipher_suite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
      forward_secrecy: "supported",
      certificate_state: "expired",
      findings_count: 1,
      first_seen: "2026-09-21T12:00:00Z",
      last_seen: "2026-09-21T12:00:00.048Z",
      has_capture_evidence: true,
      session: {
        session_id: "3779da6e-6324-5aca-84b5-06cde5297384",
        sensor_id: "sensor-local-01",
        provenance: {
          source: "pcap",
          parser: "zeek",
          parser_version: "zeek version 8.0.4",
        },
        flow: {
          src_ip: "127.0.0.1",
          src_port: 41580,
          dst_ip: "127.0.0.1",
          dst_port: 25,
        },
        protocol: "smtp",
        starttls_state: "tls_established",
        tls_version: "TLSv1.2",
        cipher_suite: {
          id: 49199,
          name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        },
        certificate: {
          reference: {
            sha256_fingerprint:
              "e714bc098be8370c1c82fa7d2cdaf60ca8534368198de0527ce887f5a84f99c6",
            subject: "CN=mail.mailent.test",
            issuer: "CN=mail.mailent.test",
          },
          validity: {
            not_before: "2020-01-01T00:00:00Z",
            not_after: "2021-01-01T00:00:00Z",
          },
          san: ["mail.mailent.test"],
        },
        capture: {
          capture_sha256:
            "ec0ed1deac16ebb45e3e4693bf61d219a606d5fa1bec0648212880bf82769414",
          connection_uid: "CJKFoj4bpHEhTeaRoj",
          normalizer_version: "mailent-zeek/1",
          source_logs: ["conn.log:1", "mailent.log:1"],
          timeline: [
            {
              timestamp: "2026-09-21T12:00:00.000016Z",
              kind: "tcp_connected",
              source: "mailent.log:1",
            },
            {
              timestamp: "2026-09-21T12:00:00.040195Z",
              kind: "smtp_greeting",
              source: "mailent.log:2",
            },
            {
              timestamp: "2026-09-21T12:00:00.040834Z",
              kind: "ehlo",
              source: "mailent.log:4",
            },
            {
              timestamp: "2026-09-21T12:00:00.040990Z",
              kind: "starttls_advertised",
              source: "mailent.log:5",
            },
            {
              timestamp: "2026-09-21T12:00:00.042198Z",
              kind: "starttls_requested",
              source: "mailent.log:7",
            },
            {
              timestamp: "2026-09-21T12:00:00.042300Z",
              kind: "starttls_accepted",
              source: "mailent.log:8",
            },
            {
              timestamp: "2026-09-21T12:00:00.042597Z",
              kind: "tls_client_hello",
              source: "mailent.log:9",
            },
            {
              timestamp: "2026-09-21T12:00:00.045147Z",
              kind: "tls_server_hello",
              source: "mailent.log:10",
            },
            {
              timestamp: "2026-09-21T12:00:00.045147Z",
              kind: "certificate_observed",
              source: "mailent.log:11",
            },
            {
              timestamp: "2026-09-21T12:00:00.048048Z",
              kind: "tls_established",
              source: "mailent.log:13",
            },
          ],
          gaps: [],
          tls_established: true,
        },
        first_seen: "2026-09-21T12:00:00Z",
        last_seen: "2026-09-21T12:00:00.048Z",
      },
    };

    const mockDetail = {
      session: mockSession.session,
      findings: [
        {
          id: "f-cert-expired",
          rule_id: "CERTIFICATE_EXPIRED",
          policy_name: "modern",
          policy_version: "1.0.0",
          reference: "rfc5280",
          severity: "high" as const,
          category: "certificate_validation",
          title: "Expired Leaf Certificate Presented",
          description: "Presented leaf certificate is expired.",
          remediation: "Renew certificate.",
          affected_count: 1,
          first_seen: "2026-09-21T12:00:00Z",
          last_seen: "2026-09-21T12:00:00.048Z",
          evidence: [
            {
              session_id: mockSession.session_id,
              observation_id: mockSession.session_id,
              description: "Certificate expired 2021-01-01",
            },
          ],
        },
      ],
      forward_secrecy: "supported" as const,
      certificate_state: "expired",
    };

    const fetcher = vi.fn((url: string) => {
      if (url === "/ready") return Promise.resolve(response(ready));
      if (url === "/api/v1/sessions")
        return Promise.resolve(response([mockSession]));
      if (url.includes("/api/v1/sessions/"))
        return Promise.resolve(response(mockDetail));
      return Promise.reject(new Error(`unexpected URL: ${url}`));
    });

    const user = setup(fetcher, "sessions");
    await screen.findByText("Connected");

    expect(
      await screen.findByRole("heading", { name: "Sessions" }),
    ).toBeVisible();
    expect(screen.getByText("127.0.0.1:41580")).toBeVisible();
    expect(screen.getByText("127.0.0.1:25")).toBeVisible();
    expect(screen.getByText("TLSv1.2")).toBeVisible();
    expect(screen.getByText("tls_established")).toBeVisible();

    const inspectBtn = screen.getByRole("button", { name: "Inspect" });
    await user.click(inspectBtn);

    expect(await screen.findByText("SESSION DETAILS")).toBeVisible();
    expect(screen.getByText("Session Timeline")).toBeVisible();
    expect(screen.getByText("TCP connected")).toBeVisible();
    expect(screen.getByText("mailent.log:1")).toBeVisible();
    expect(screen.getByText("SMTP greeting")).toBeVisible();
    expect(screen.getByText("EHLO")).toBeVisible();
    expect(screen.getByText("STARTTLS advertised")).toBeVisible();
    expect(screen.getByText("TLS ClientHello")).toBeVisible();
    expect(screen.getByText("TLS ServerHello")).toBeVisible();
    expect(screen.getByText("Certificate observed")).toBeVisible();
    expect(screen.getByText("TLS established")).toBeVisible();
    expect(screen.getByText("CERTIFICATE_EXPIRED")).toBeVisible();
  });

  it("renders findings view with policy findings and evidence", async () => {
    const mockFinding = {
      id: "f-legacy-tls",
      rule_id: "TLS_LEGACY_VERSION",
      policy_name: "modern",
      policy_version: "1.0.0",
      reference: "rfc8996",
      severity: "critical" as const,
      category: "tls_configuration",
      title: "Deprecated TLS Version Negotiated",
      description: "TLS 1.0 is deprecated under RFC 8996.",
      remediation: "Upgrade to TLS 1.2/1.3.",
      affected_count: 1,
      first_seen: "2026-09-21T12:00:00Z",
      last_seen: "2026-09-21T12:00:00Z",
      evidence: [
        {
          session_id: "s-1234",
          observation_id: "o-1234",
          description: "Observed TLS 1.0 handshake",
        },
      ],
    };

    const fetcher = vi.fn((url: string) => {
      if (url === "/ready") return Promise.resolve(response(ready));
      if (url.startsWith("/api/v1/findings"))
        return Promise.resolve(response([mockFinding]));
      return Promise.reject(new Error(`unexpected URL: ${url}`));
    });

    setup(fetcher, "findings");
    await screen.findByText("Connected");

    expect(
      await screen.findByRole("heading", { name: "Findings" }),
    ).toBeVisible();
    expect(screen.getByText("TLS_LEGACY_VERSION")).toBeVisible();
    expect(screen.getByText("Deprecated TLS Version Negotiated")).toBeVisible();
    expect(screen.getByText("Upgrade to TLS 1.2/1.3.")).toBeVisible();
  });

  it("renders assets inventory and inspects asset details", async () => {
    const mockAsset = {
      id: "a1b2c3d4-0000-0000-0000-000000000001",
      primary_name: "mail.mailent.test",
      addresses: ["127.0.0.1"],
      hostnames: ["mail.mailent.test"],
      identities: [
        {
          kind: "ehlo",
          value: "mail.mailent.test",
          first_seen: "2026-09-22T10:00:00Z",
          last_seen: "2026-09-22T10:00:00Z",
        },
      ],
      endpoints: [
        {
          protocol: "smtp",
          port: 25,
          tls_versions: ["TLSv1.3"],
          cipher_suites: ["TLS_AES_256_GCM_SHA384"],
          first_seen: "2026-09-22T10:00:00Z",
          last_seen: "2026-09-22T10:00:00Z",
        },
      ],
      tls_versions: ["TLSv1.3"],
      cipher_suites: ["TLS_AES_256_GCM_SHA384"],
      certificate_fingerprints: [
        "e714bc098be8370c1c82fa7d2cdaf60ca8534368198de0527ce887f5a84f99c6",
      ],
      active_findings_count: 0,
      first_seen: "2026-09-22T10:00:00Z",
      last_seen: "2026-09-22T10:00:00Z",
    };

    const mockDrift = [
      {
        id: "drift-1",
        asset_id: mockAsset.id,
        kind: "NewTlsVersion",
        title: "New TLS Version Observed",
        description: "TLSv1.3 negotiated for the first time.",
        previous_value: null,
        new_value: "TLSv1.3",
        observed_at: "2026-09-22T10:00:00Z",
        session_id: "s-1",
      },
    ];

    const mockCert = [
      {
        sha256_fingerprint:
          "e714bc098be8370c1c82fa7d2cdaf60ca8534368198de0527ce887f5a84f99c6",
        subject: "CN=mail.mailent.test",
        issuer: "CN=Let's Encrypt",
        sans: ["mail.mailent.test"],
        not_before: "2026-01-01T00:00:00Z",
        not_after: "2027-01-01T00:00:00Z",
        first_seen: "2026-09-22T10:00:00Z",
        last_seen: "2026-09-22T10:00:00Z",
        associated_asset_ids: [mockAsset.id],
      },
    ];

    const mockPosture = {
      posture: {
        id: "p-1",
        score_version: "1.0.0",
        subject_kind: "asset",
        subject_id: mockAsset.id,
        score: 25,
        grade: "critical",
        score_capped: true,
        pre_cap_score: 82,
        categories: [
          {
            category: "transport_security",
            score: 30,
            weight: 0.4,
            weighted_score: 12,
            finding_rule_ids: ["TLS_LEGACY_VERSION"],
            rationale: "Deductions applied.",
          },
          {
            category: "certificate_hygiene",
            score: 100,
            weight: 0.25,
            weighted_score: 25,
            finding_rule_ids: [],
            rationale: "No deductions.",
          },
          {
            category: "protocol_configuration",
            score: 100,
            weight: 0.25,
            weighted_score: 25,
            finding_rule_ids: [],
            rationale: "No deductions.",
          },
          {
            category: "anomaly_risk_context",
            score: 100,
            weight: 0.1,
            weighted_score: 10,
            finding_rule_ids: [],
            rationale: "No signals.",
          },
        ],
        deductions: [
          {
            rule_id: "TLS_LEGACY_VERSION",
            finding_id: "f-1",
            severity: "critical",
            category: "transport_security",
            points: 70,
            evidence_description: "Observed TLS 1.0",
          },
        ],
        worst_findings: ["TLS_LEGACY_VERSION"],
        findings_considered: 1,
        computed_at: "2026-09-22T10:00:00Z",
      },
      guidance: [
        {
          id: "g-1",
          kind: "remediation",
          finding_id: "f-1",
          rule_id: "TLS_LEGACY_VERSION",
          title: "Deprecated TLS Version Negotiated",
          observed: "Observed TLS 1.0 on connection",
          why_it_matters: "Legacy TLS is deprecated.",
          recommendation: "Disable TLS 1.0/1.1.",
          recommended_state: "TLS 1.2 minimum.",
          compatibility_caveats: [
            "Observed compatibility: 2 historical peer(s) negotiated legacy TLS.",
          ],
          verification: "Run an active Mailent probe.",
          evidence: [
            {
              session_id: null,
              observation_id: "o-1",
              description: "Observed TLS 1.0",
            },
          ],
          severity: "critical",
          category: "tls_configuration",
          generated_at: "2026-09-22T10:00:00Z",
        },
        {
          id: "g-2",
          kind: "best_practice",
          finding_id: null,
          rule_id: "BP_ENABLE_TLS13",
          title: "TLS 1.3 not observed on this asset",
          observed: "No TLS 1.3 handshake observed.",
          why_it_matters: "Hardening.",
          recommendation: "Enable TLS 1.3.",
          recommended_state: "TLS 1.3 enabled.",
          compatibility_caveats: [],
          verification: "Verify passively.",
          evidence: [],
          severity: "low",
          category: "tls_configuration",
          generated_at: "2026-09-22T10:00:00Z",
        },
      ],
    };

    const fetcher = vi.fn((url: string) => {
      if (url === "/ready") return Promise.resolve(response(ready));
      if (url === "/api/v1/assets")
        return Promise.resolve(response([mockAsset]));
      if (url === `/api/v1/assets/${mockAsset.id}`)
        return Promise.resolve(response(mockAsset));
      if (url === `/api/v1/assets/${mockAsset.id}/posture`)
        return Promise.resolve(response(mockPosture));
      if (url === `/api/v1/assets/${mockAsset.id}/drift`)
        return Promise.resolve(response(mockDrift));
      if (url === `/api/v1/assets/${mockAsset.id}/certificates`)
        return Promise.resolve(response(mockCert));
      if (url === `/api/v1/assets/${mockAsset.id}/findings`)
        return Promise.resolve(response([]));
      if (url === `/api/v1/assets/${mockAsset.id}/sessions`)
        return Promise.resolve(response([]));
      return Promise.reject(new Error(`unexpected URL: ${url}`));
    });

    const user = setup(fetcher, "assets");
    await screen.findByText("Connected");

    expect(
      await screen.findByRole("heading", { name: "Mail servers" }),
    ).toBeVisible();
    expect(screen.getByText("mail.mailent.test")).toBeVisible();
    expect(screen.getByText("127.0.0.1")).toBeVisible();

    const inspectBtn = screen.getByRole("button", { name: "View server" });
    await user.click(inspectBtn);

    expect(await screen.findByText("SERVER DETAILS")).toBeVisible();
    expect(await screen.findByText("New TLS Version Observed")).toBeVisible();
    expect(
      screen.getByText("TLSv1.3 negotiated for the first time."),
    ).toBeVisible();
    expect(screen.getByText("CN=Let's Encrypt")).toBeVisible();

    // Posture surface: versioned model, capped score, category breakdown.
    expect(
      await screen.findByText("Security Posture (model v1.0.0)"),
    ).toBeVisible();
    expect(screen.getByText("25 / 100")).toBeVisible();
    expect(screen.getByText("82 → 25")).toBeVisible();
    expect(screen.getByText("transport security")).toBeVisible();
    const postureSection = screen
      .getByLabelText("Security Posture")
      .closest("section");
    expect(postureSection).toHaveTextContent("TLS_LEGACY_VERSION");

    // Guidance surfaces stay distinct: Remediation vs Best Practice.
    expect(await screen.findByText("Remediation Guidance (1)")).toBeVisible();
    expect(screen.getByText("Observed compatibility caveats")).toBeVisible();
    expect(
      screen.getByText(/2 historical peer\(s\) negotiated legacy TLS/),
    ).toBeVisible();
    expect(screen.getByText("Best Practice Guidance (1)")).toBeVisible();
    expect(screen.getByText("Best Practice")).toBeVisible();
    expect(screen.getByText("Enable TLS 1.3.")).toBeVisible();

    // Forensic report export surface present for the analyst.
    expect(await screen.findByText("Forensic Report")).toBeVisible();
    expect(screen.getByRole("button", { name: "Export JSON" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Export HTML" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Export PDF" })).toBeEnabled();
  });

  it("renders sensors list and telemetry status", async () => {
    const mockSensor = {
      sensor_id: "sensor-gateway-01",
      site_id: "edge-pop-ams",
      hostname: "sensor-node.prod.internal",
      version: "0.1.0",
      mode: "live",
      interface: "eth0",
      status: "Online" as const,
      last_seen: "2026-09-22T10:00:00Z",
      registered_at: "2026-09-22T08:00:00Z",
    };

    const fetcher = vi.fn((url: string) => {
      if (url === "/ready") return Promise.resolve(response(ready));
      if (url === "/api/v1/sensors")
        return Promise.resolve(response([mockSensor]));
      return Promise.reject(new Error(`unexpected URL: ${url}`));
    });

    setup(fetcher, "sensors");
    await screen.findByText("Connected");

    expect(
      await screen.findByRole("heading", { name: "Collectors" }),
    ).toBeVisible();
    expect(screen.getByText("sensor-gateway-01")).toBeVisible();
    expect(screen.getByText("sensor-node.prod.internal")).toBeVisible();
    expect(screen.getByText("eth0")).toBeVisible();
    expect(screen.getByText("Online")).toBeVisible();
  });
});
