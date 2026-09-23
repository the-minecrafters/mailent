import { expect, test } from "@playwright/test";

test("development evaluator renders the core findings for each observation", async ({
  page,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/tools/evaluator");
  await expect(page.getByText("Connected")).toBeVisible();
  await expect(page.getByText("No observation evaluated")).toBeVisible();
  for (const [fixture, rules] of [
    ["legacy", ["TLS_LEGACY_VERSION", "NO_FORWARD_SECRECY"]],
    ["expired", ["CERTIFICATE_EXPIRED"]],
    ["rsa", ["NO_FORWARD_SECRECY"]],
    ["modern", []],
  ] as const) {
    await page.getByLabel("Synthetic fixture").selectOption(fixture);
    const responsePromise = page.waitForResponse((response) =>
      response.url().includes("/observations/evaluate"),
    );
    await page.getByRole("button", { name: "Evaluate observation" }).click();
    const response = await responsePromise;
    expect(response.status()).toBe(200);
    const data = await response.json();
    expect(
      data.findings.map((f: { rule_id: string }) => f.rule_id).sort(),
    ).toEqual([...rules].sort());
    await expect(page.getByText(`${rules.length} Finding(s)`, { exact: true })).toBeVisible();
    await expect(page.getByText(`Session: ${data.session_id}`, { exact: true })).toBeVisible();
    for (const rule of rules)
      await expect(page.getByText(rule, { exact: true })).toBeVisible();
    if (fixture === "legacy") {
      await page.screenshot({
        path: "test-results/evaluation-desktop.png",
        fullPage: true,
      });
    }
    if (!rules.length) {
      await expect(
        page.getByText("No violations found by the evaluated rules"),
      ).toBeVisible();
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByLabel("Synthetic fixture").selectOption("legacy");
  await page.getByRole("button", { name: "Evaluate observation" }).click();
  await expect(page.getByText("2 Finding(s)", { exact: true })).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/evaluation-mobile.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
});

test("real captured sessions view displays forensic timeline and inspector", async ({
  page,
  request,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));

  // Post an observation with capture timeline
  const res = await request.post("http://127.0.0.1:18080/api/v1/observations", {
    headers: { "Content-Type": "application/json" },
    data: {
      observation_id: "e0000000-0000-0000-0000-000000000001",
      timestamp: "2026-09-22T12:00:00Z",
      sensor_id: "sensor-e2e-01",
      flow: {
        src_ip: "192.0.2.100",
        src_port: 54320,
        dst_ip: "203.0.113.25",
        dst_port: 25,
      },
      protocol: "smtp",
      starttls_state: "advertised_and_used",
      tls_version: "TLSv1.3",
      cipher_suite: {
        id: 4867,
        name: "TLS_AES_256_GCM_SHA384",
      },
      key_exchange: "ecdhe",
      certificate: {
        reference: {
          sha256_fingerprint:
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          subject: "CN=mail.example.org",
          issuer: "CN=Example Root CA",
        },
        validity: {
          not_before: "2024-01-01T00:00:00Z",
          not_after: "2027-01-01T00:00:00Z",
        },
        is_self_signed: false,
        san: ["mail.example.org"],
      },
      capture: {
        capture_sha256:
          "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        connection_uid: "Ce2eTest00001",
        normalizer_version: "0.1.0",
        source_logs: ["conn.log", "smtp.log", "ssl.log"],
        timeline: [
          {
            timestamp: "2026-09-22T12:00:00.100000Z",
            kind: "tcp_connected",
            source: "conn.log:1",
          },
          {
            timestamp: "2026-09-22T12:00:00.200000Z",
            kind: "smtp_greeting",
            source: "smtp.log:1",
          },
          {
            timestamp: "2026-09-22T12:00:00.300000Z",
            kind: "starttls_advertised",
            source: "smtp.log:1",
          },
          {
            timestamp: "2026-09-22T12:00:00.400000Z",
            kind: "tls_server_hello",
            source: "ssl.log:1",
          },
        ],
        gaps: [],
        tls_established: true,
        protocol_hint: null,
      },
      provenance: {
        source: "pcap",
        parser: "zeek",
        parser_version: "7.0.0",
      },
    },
  });
  expect(res.ok()).toBe(true);

  await page.goto("/workspace/overview");
  await expect(page.getByText("Connected")).toBeVisible();
  await page.getByRole("link", { name: "Sessions", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sessions", exact: true })).toBeVisible();

  const targetRow = page.locator("tr", { hasText: "192.0.2.100:54320" });
  await expect(targetRow).toBeVisible();
  await targetRow.getByRole("button", { name: /inspect/i }).click();

  await expect(page.getByText("SESSION DETAILS")).toBeVisible();
  await expect(page.getByText("Session Timeline")).toBeVisible();
  await expect(page.getByText("TCP connected")).toBeVisible();
  await expect(page.getByText("STARTTLS advertised")).toBeVisible();
  await expect(page.getByText("TLS ServerHello")).toBeVisible();
  await expect(page.getByText("CN=mail.example.org")).toBeVisible();

  expect(errors).toEqual([]);
});

test("persistent assets, drift events, and sensor telemetry UI", async ({
  page,
  request,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));

  // 1. Post a sensor heartbeat
  const hbRes = await request.post(
    "http://127.0.0.1:18080/api/v1/sensors/heartbeat",
    {
      headers: { "Content-Type": "application/json" },
      data: {
        sensor_id: "sensor-e2e-tap-01",
        site_id: "lab-chicago",
        hostname: "tap.local",
        version: "0.1.0",
        mode: "live",
        interface: "eth0",
        observations_processed: 10,
        observations_spooled: 0,
        observations_dropped: 0,
      },
    },
  );
  expect(hbRes.ok()).toBe(true);

  // 2. Post initial observation (TLS 1.2)
  const obs1Res = await request.post(
    "http://127.0.0.1:18080/api/v1/observations",
    {
      headers: { "Content-Type": "application/json" },
      data: {
        observation_id: "e0000000-0000-0000-0000-000000000010",
        timestamp: "2026-09-22T13:00:00Z",
        sensor_id: "sensor-e2e-tap-01",
        flow: {
          src_ip: "10.0.0.1",
          src_port: 50000,
          dst_ip: "10.0.0.25",
          dst_port: 25,
        },
        protocol: "smtp",
        starttls_state: "advertised_and_used",
        tls_version: "TLSv1.2",
        cipher_suite: {
          id: 49199,
          name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        },
        key_exchange: "ecdhe",
        certificate: {
          reference: {
            sha256_fingerprint:
              "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            subject: "CN=smtp.corp.local",
            issuer: "CN=Internal Corporate CA",
          },
          validity: {
            not_before: "2025-01-01T00:00:00Z",
            not_after: "2028-01-01T00:00:00Z",
          },
          is_self_signed: false,
          san: ["smtp.corp.local"],
        },
        provenance: {
          source: "pcap",
          parser: "zeek",
          parser_version: "7.0.0",
        },
      },
    },
  );
  expect(obs1Res.ok()).toBe(true);

  // 3. Post second observation triggering configuration drift (TLS 1.3)
  const obs2Res = await request.post(
    "http://127.0.0.1:18080/api/v1/observations",
    {
      headers: { "Content-Type": "application/json" },
      data: {
        observation_id: "e0000000-0000-0000-0000-000000000011",
        timestamp: "2026-09-22T13:05:00Z",
        sensor_id: "sensor-e2e-tap-01",
        flow: {
          src_ip: "10.0.0.2",
          src_port: 50002,
          dst_ip: "10.0.0.25",
          dst_port: 25,
        },
        protocol: "smtp",
        starttls_state: "advertised_and_used",
        tls_version: "TLSv1.3",
        cipher_suite: {
          id: 4867,
          name: "TLS_AES_256_GCM_SHA384",
        },
        key_exchange: "ecdhe",
        certificate: {
          reference: {
            sha256_fingerprint:
              "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            subject: "CN=smtp.corp.local",
            issuer: "CN=Internal Corporate CA",
          },
          validity: {
            not_before: "2025-01-01T00:00:00Z",
            not_after: "2028-01-01T00:00:00Z",
          },
          is_self_signed: false,
          san: ["smtp.corp.local"],
        },
        provenance: {
          source: "pcap",
          parser: "zeek",
          parser_version: "7.0.0",
        },
      },
    },
  );
  expect(obs2Res.ok()).toBe(true);

  // 4. Navigate and check Sensors tab
  await page.goto("/workspace/overview");
  await expect(page.getByText("Connected")).toBeVisible();

  await page.getByRole("link", { name: "Collectors", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Collectors", exact: true })).toBeVisible();
  await expect(page.getByText("sensor-e2e-tap-01")).toBeVisible();
  await expect(page.getByText("tap.local")).toBeVisible();
  await expect(page.getByText("Online")).toBeVisible();

  // 5. Check Assets tab and verify drift + certs
  await page.getByRole("link", { name: "Mail servers", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Mail servers", exact: true })).toBeVisible();
  const assetRow = page.locator("tr", { hasText: "10.0.0.25" });
  await expect(assetRow).toBeVisible();
  // Resolve the asset id from the API for the report assertions below.
  const assetsResponse = await page.request.get(
    "http://127.0.0.1:18080/api/v1/assets",
  );
  const assets = await assetsResponse.json();
  const assetId = assets.find((a: { addresses: string[] }) =>
    a.addresses.includes("10.0.0.25"),
  ).id as string;
  await assetRow.getByRole("button", { name: /view server/i }).click();

  await expect(page.getByText("SERVER DETAILS")).toBeVisible();
  await expect(page.getByRole("heading", { name: /Configuration changes/ })).toBeVisible();
  await expect(page.getByText("New TLS Version Detected")).toBeVisible();
  await expect(page.getByRole("heading", { name: /Certificate history/ })).toBeVisible();
  await expect(page.getByText("CN=Internal Corporate CA")).toBeVisible();

  // Deterministic posture scoring surface: versioned model with categories.
  await expect(page.getByText("Security Posture (model v1.0.0)")).toBeVisible();
  await expect(
    page.getByText("transport security", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("certificate hygiene", { exact: true }),
  ).toBeVisible();
  // No policy findings were correlated for this healthy asset.
  await expect(page.getByText("Remediation Guidance (0)")).toBeVisible();
  await expect(page.getByText(/Best Practice Guidance \(\d+\)/)).toBeVisible();

  // Forensic report export: JSON endpoint returns complete evidence for this
  // asset (real backend, no mocks).
  const reportResponse = await page.request.get(
    `http://127.0.0.1:18080/api/v1/assets/${assetId}/report?format=json`,
  );
  expect(reportResponse.status()).toBe(200);
  const report = await reportResponse.json();
  expect(report.metadata.policy_name).toBe("modern");
  expect(report.sessions.length).toBeGreaterThan(0);
  expect(report.sessions[0].tls_version).toMatch(/TLSv1\.[23]/);
  expect(report.posture).toBeTruthy();
  expect(Array.isArray(report.remediation)).toBe(true);
  expect(Array.isArray(report.best_practices)).toBe(true);
  // Human formats exist and carry the session's server address.
  const htmlReport = await page.request.get(
    `http://127.0.0.1:18080/api/v1/assets/${assetId}/report?format=html`,
  );
  expect(htmlReport.status()).toBe(200);
  const html = await htmlReport.text();
  expect(html).toContain("10.0.0.25");
  expect(html).toContain("observed fact");
  const pdfResponse = await page.request.get(
    `http://127.0.0.1:18080/api/v1/assets/${assetId}/report?format=pdf`,
  );
  expect(pdfResponse.status()).toBe(200);
  const pdfBuffer = await pdfResponse.body();
  expect(pdfBuffer.subarray(0, 8).toString("latin1")).toContain("%PDF");

  expect(errors).toEqual([]);
});
