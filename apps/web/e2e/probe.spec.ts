import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

test("real SMTP capture is verified from its asset and enriches the linked investigation", async ({
  page,
  request,
}) => {
  const capture = process.env.MAILENT_PROBE_TEST_CAPTURE;
  test.skip(
    !capture,
    "requires a fresh TLS 1.2 capture from the running local probe lab",
  );
  const analysis = JSON.parse(readFileSync(capture as string, "utf8"));
  const observation = analysis.observations.find(
    (o: { protocol: string }) => o.protocol === "smtp",
  );
  expect(observation.provenance.source).toBe("pcap");
  const imported = await request.post(
    "http://127.0.0.1:18080/api/v1/observations",
    { data: observation },
  );
  expect(imported.ok()).toBe(true);
  const { asset_id: assetId } = await imported.json();
  const all = await (
    await request.get("http://127.0.0.1:18080/api/v1/investigations")
  ).json();
  const investigation = all.find(
    (i: { asset_id: string }) => i.asset_id === assetId,
  );
  expect(investigation).toBeTruthy();
  await page.goto("/");
  await page.getByRole("link", { name: "Mail servers", exact: true }).click();
  const row = page.locator("tr", { hasText: "127.0.0.1" });
  await row.getByRole("button", { name: /view/i }).click();
  await page.getByRole("combobox", { name: "Protocol" }).selectOption("smtp");
  await page
    .getByRole("spinbutton", { name: "Port" })
    .fill(String(observation.flow.dst_port));
  await page
    .getByRole("combobox", { name: "Investigation" })
    .selectOption(investigation.id);
  await expect(
    page.getByRole("button", { name: "Verify transport" }),
  ).toBeEnabled();
  const response = page.waitForResponse(
    (r) =>
      r.url().endsWith(`/assets/${assetId}/probe`) &&
      r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Verify transport" }).click();
  const accepted = await response;
  expect(accepted.status()).toBe(202);
  const { probe_id: probeId } = await accepted.json();
  await expect
    .poll(
      async () =>
        (
          await (
            await request.get(`http://127.0.0.1:18080/api/v1/probes/${probeId}`)
          ).json()
        ).finished_at,
    )
    .not.toBeNull();
  const run = await (
    await request.get(`http://127.0.0.1:18080/api/v1/probes/${probeId}`)
  ).json();
  expect(run.outcome).toBe("success");
  expect(run.result.starttls).toBe("advertised_and_accepted");
  expect(run.result.certificate.reference.sha256_fingerprint).toBe(
    observation.certificate.reference.sha256_fingerprint,
  );
  expect(run.result.verification.passive_session_id).toBe(
    observation.observation_id,
  );
  expect(
    run.perspective_mismatches.some(
      (m: { kind: string }) => m.kind === "tls_version",
    ),
  ).toBe(true);
  await expect(
    page.getByText(/tls_version: TLSv1.2 → TLSv1.3/).first(),
  ).toBeVisible();
  await page.getByText("Certificate evidence", { exact: true }).first().click();
  await expect(
    page
      .getByText(
        `SHA-256: ${observation.certificate.reference.sha256_fingerprint}`,
      )
      .first(),
  ).toBeVisible();
  await expect
    .poll(async () => {
      const inv = await (
        await request.get(
          `http://127.0.0.1:18080/api/v1/investigations/${investigation.id}`,
        )
      ).json();
      expect(inv.status).toBe(investigation.status);
      return inv.external_intelligence.active_verifications?.[probeId]?.id;
    })
    .toBe(probeId);
  await page.screenshot({
    path: "test-results/probe-evidence.png",
    fullPage: true,
  });
});
