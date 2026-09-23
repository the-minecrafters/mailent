import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

test("real captured certificate problem is remediated through guidance with preserved evidence", async ({
  page,
  request,
}) => {
  test.setTimeout(90000);
  const capture = process.env.MAILENT_REMEDIATION_CAPTURE;
  const lab = process.env.MAILENT_REMEDIATION_LAB;
  test.skip(
    !capture || !lab,
    "requires disposable local mail lab and fresh expired-certificate capture",
  );
  expect(lab).toMatch(/^mailent-probe-/);
  const observation = JSON.parse(readFileSync(capture as string, "utf8"))
    .observations[0];
  expect(observation.provenance.source).toBe("pcap");
  const base = "http://127.0.0.1:18080/api/v1";
  const response = await request.post(`${base}/observations`, {
    data: observation,
  });
  expect(response.ok()).toBe(true);
  const imported = await response.json();
  const original = imported.findings.find(
    (f: { rule_id: string }) => f.rule_id === "CERTIFICATE_EXPIRED",
  );
  expect(original).toBeTruthy();
  const investigations = await (
    await request.get(`${base}/investigations`)
  ).json();
  const originalInvestigation = investigations.find(
    (i: { asset_id: string }) => i.asset_id === imported.asset_id,
  );
  expect(originalInvestigation).toBeTruthy();
  await page.goto("/");
  await page.getByRole("tab", { name: /assets/i }).click();
  await page
    .locator("tr", { hasText: "127.0.0.1" })
    .getByRole("button", { name: /view/i })
    .click();
  const workflow = page.getByRole("region", {
    name: "Remediation workflow CERTIFICATE_EXPIRED",
  });
  await workflow.getByRole("button", { name: "Start remediation" }).click();
  await expect(
    workflow.getByText("Remediation: in progress", { exact: true }),
  ).toBeVisible();
  await workflow
    .getByLabel("Change note")
    .fill("Checking the unchanged expired certificate");
  await workflow.getByRole("button", { name: "Mark change applied" }).click();
  await expect(
    workflow.getByText("Remediation: applied", { exact: true }),
  ).toBeVisible();
  const acceptedPromise = page.waitForResponse(
    (r) => r.url().endsWith("/verify") && r.request().method() === "POST",
  );
  await workflow.getByRole("button", { name: "Verify fix" }).click();
  const accepted = await acceptedPromise;
  expect(accepted.status()).toBe(202);
  const started = await accepted.json();
  await expect(
    workflow.getByText("Remediation: still present", { exact: true }),
  ).toBeVisible({ timeout: 20000 });
  execFileSync(
    "podman",
    ["exec", lab as string, "python3", "/tmp/rotate_certificate.py", "valid"],
    { timeout: 15000 },
  );
  await workflow
    .getByLabel("Change note")
    .fill("Renewed the certificate using the lab CA");
  await workflow.getByRole("button", { name: "Mark change applied" }).click();
  await expect(
    workflow.getByText("Remediation: applied", { exact: true }),
  ).toBeVisible();
  await expect
    .poll(async () => {
      const r = await (
        await request.get(`${base}/remediations/${started.id}`)
      ).json();
      return Date.now() - Date.parse(r.attempts[0].completed_at) > 1100;
    })
    .toBe(true);
  await workflow.getByRole("button", { name: "Verify fix" }).click();
  await expect(
    workflow.getByText("Remediation: verified fixed", { exact: true }),
  ).toBeVisible({ timeout: 20000 });
  await workflow
    .getByText("Original policy and passive evidence", { exact: true })
    .click();
  await expect(
    workflow.getByText(
      `Certificate ${observation.certificate.reference.sha256_fingerprint}`,
      { exact: true },
    ),
  ).toBeVisible();
  const record = await (
    await request.get(`${base}/remediations/${started.id}`)
  ).json();
  expect(record.finding).toEqual(original);
  expect(record.before.session_id).toBe(observation.observation_id);
  expect(record.attempts).toHaveLength(2);
  const after = record.attempts[1].after.result;
  expect(after.certificate_trusted).toBe(true);
  expect(after.certificate_hostname_valid).toBe(true);
  expect(after.starttls).toBe("advertised_and_accepted");
  const last = record.attempts[1];
  const replay = await request.post(
    `${base}/remediations/${started.id}/verify`,
    { data: { request_id: last.request_id } },
  );
  expect((await replay.json()).attempts).toHaveLength(2);
  const inv = await (
    await request.get(`${base}/investigations/${originalInvestigation.id}`)
  ).json();
  expect(inv.status).toBe(originalInvestigation.status);
  expect(inv.remediations[0].state).toBe("verified_fixed");
  const report = await (
    await request.get(
      `${base}/investigations/${originalInvestigation.id}/report?format=json`,
    )
  ).json();
  expect(report.remediation_lifecycle[0].state).toBe("verified_fixed");
  expect(
    report.findings.some(
      (f: { rule_id: string }) => f.rule_id === "CERTIFICATE_EXPIRED",
    ),
  ).toBe(true);
  const training = await (
    await request.get(
      `${base}/training?investigation_id=${originalInvestigation.id}`,
    )
  ).json();
  expect(
    training.some(
      (r: { remediation_outcomes: Record<string, { outcome: string }> }) =>
        r.remediation_outcomes[last.request_id]?.outcome === "verified_fixed",
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/remediation-fixed.png",
    fullPage: true,
  });
  await page.reload();
  await page.getByRole("tab", { name: /assets/i }).click();
  await page
    .locator("tr", { hasText: "127.0.0.1" })
    .getByRole("button", { name: /view/i })
    .click();
  await expect(
    page.getByText("Remediation: verified fixed", { exact: true }),
  ).toBeVisible();
});
