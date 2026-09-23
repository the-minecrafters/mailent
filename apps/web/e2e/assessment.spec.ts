import path from "node:path";
import { expect, test } from "@playwright/test";

test("capture upload, routed evidence, downloads, and responsive navigation", async ({
  page,
}) => {
  test.setTimeout(120000);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/workspace/overview");
  await expect(
    page.getByRole("heading", {
      name: "Overview",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Analyze capture", exact: true }),
  ).toHaveCount(1);
  await page
    .getByRole("button", { name: "Analyze capture", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByRole("button", { name: "Analyze capture", exact: true }),
  ).toBeDisabled();
  await dialog.locator("input[type=file]").setInputFiles({
    name: "bad.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("not a capture"),
  });
  await expect(
    dialog.getByText("Choose a PCAP, PCAPNG or CAP file."),
  ).toBeVisible();
  await dialog
    .locator("input[type=file]")
    .setInputFiles(path.resolve("../../fixtures/pcap/smtp_legacy.pcap"));
  await expect(
    dialog.getByRole("button", { name: "Analyze capture", exact: true }),
  ).toBeEnabled();
  const analysis = page.waitForResponse(
    (r) =>
      r.url().endsWith("/api/v1/assessments/analyze") &&
      r.request().method() === "POST",
    { timeout: 65000 },
  );
  await dialog
    .getByRole("button", { name: "Analyze capture", exact: true })
    .click();
  const response = await analysis;
  expect(response.status(), await response.text()).toBe(201);
  const capture = await response.json();
  await expect(page).toHaveURL(new RegExp(`/captures/${capture.id}`));
  await expect(dialog).not.toBeVisible();
  await page.getByRole("button", { name: /^Sessions \(/ }).click();
  await expect(page).toHaveURL(/tab=sessions/);
  await page.reload();
  await expect(
    page.getByRole("button", { name: /^Sessions \(/ }),
  ).toHaveAttribute("aria-current", "page");
  await page.getByRole("button", { name: /^Findings \(/ }).click();
  await expect(page.getByText("TLS_LEGACY_VERSION").first()).toBeVisible();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON", exact: true }).click();
  expect((await download).suggestedFilename()).toMatch(/\.json$/);
  await page.getByRole("link", { name: "Overview", exact: true }).click();
  await page.goBack();
  await expect(page).toHaveURL(/tab=findings/);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(400);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: "test-results/capture-mobile.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/workspace/overview");
  await page.screenshot({
    path: "test-results/overview-desktop.png",
    fullPage: true,
  });
  expect(errors).toEqual([]);
});

test("public landing opens the separate workspace", async ({ page }) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Email security, in plain sight." }),
  ).toBeVisible();
  await expect(
    page.getByRole("navigation", { name: "Main navigation" }),
  ).toHaveCount(0);
  await page.getByRole("link", { name: "Open your workspace" }).click();
  await expect(page).toHaveURL(/\/workspace\/overview$/);
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
});
