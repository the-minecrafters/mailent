import { expect, test } from "@playwright/test";

test("workspace acquisition guides guests to sign in without uploading or scanning", async ({
  page,
}) => {
  const acquisitions: string[] = [];
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      /\/assessments\/analyze|\/scans\//.test(request.url())
    )
      acquisitions.push(request.url());
  });
  await page.goto("/workspace/overview");
  for (const [action, heading] of [
    ["Analyze capture", "Analyze captures"],
    ["Scan infrastructure", "Scan mail infrastructure"],
    ["Monitor traffic", "Monitor live traffic"],
  ]) {
    await page.getByRole("button", { name: action, exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(
      dialog.getByRole("heading", { name: heading, exact: true }),
    ).toBeVisible();
    await expect(
      dialog.getByRole("button", { name: "Sign in", exact: true }),
    ).toBeVisible();
    await expect(dialog.locator("input[type=file]")).toHaveCount(0);
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
  }
  expect(acquisitions).toEqual([]);
  expect(errors).toEqual([]);
});

test("public landing explains local analysis and opens the separate workspace", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText(
    "Analyze locally.Review together.See what changed.",
  );
  await expect(
    page.getByRole("navigation", { name: "Main navigation" }),
  ).toHaveCount(0);
  await page.getByRole("link", { name: "Open workspace" }).first().click();
  await expect(page).toHaveURL(/\/workspace\/overview$/);
  await expect(
    page.getByRole("heading", { name: "Overview", exact: true }),
  ).toBeVisible();
});

test("old device links preserve approval codes and gate guests", async ({
  page,
}) => {
  await page.goto("/workspace/devices?code=MLT-VERIFY00");
  await expect(page).toHaveURL(
    /\/workspace\/installations\?code=MLT-VERIFY00$/,
  );
  await expect(
    page.getByRole("heading", { name: "Mailent installations", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Sign in", exact: true }).last(),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Connect installation", exact: true }),
  ).toHaveCount(0);
});
