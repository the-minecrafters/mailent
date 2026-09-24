import { expect, type Page, test } from "@playwright/test";

async function expectPageFits(page: Page) {
  await expect
    .poll(() =>
      page.evaluate(() => document.documentElement.scrollWidth - innerWidth),
    )
    .toBeLessThanOrEqual(1);
  const clippedControls = await page
    .locator("header button, header a, .sidebar-footer button")
    .evaluateAll((elements) =>
      elements
        .filter((el) => {
          const r = el.getBoundingClientRect();
          return r.width > 0 && (r.right > innerWidth + 1 || r.left < -1);
        })
        .map((el) => el.textContent),
    );
  expect(clippedControls).toEqual([]);
}

test("workspace pages stay within desktop bounds and use product language", async ({
  page,
}) => {
  test.setTimeout(120000);
  const routes = [
    "overview",
    "captures",
    "servers",
    "sessions",
    "findings",
    "reviews",
    "fixes",
    "reports",
    "policies",
    "integrations",
    "collectors",
    "devices",
  ];
  for (const width of [1280, 1920]) {
    await page.setViewportSize({ width, height: 1000 });
    for (const route of routes) {
      await page.goto(`/workspace/${route}`);
      await expect(page.getByRole("main")).toBeVisible();
      await expect(page.locator(".route-view h1")).toBeVisible();
      await expectPageFits(page);
      const copy = await page.getByRole("main").innerText();
      expect(copy, route).not.toMatch(
        /\b(Jev|forensic|investigation|probe|engine|PostgreSQL|persistent|non-persistent)\b/i,
      );
    }
  }
  await page.goto("/workspace/investigations");
  await expect(page).toHaveURL(/\/workspace\/reviews$/);
  await expect(
    page.getByRole("heading", { name: "Reviews", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Check domain", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expectPageFits(page);
  await expect(
    dialog.getByRole("button", { name: "Run check" }),
  ).toBeDisabled();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
});

test("sign-in is readable and privacy details have their own page", async ({
  page,
}) => {
  await page.route("**/auth/config", (route) =>
    route.fulfill({
      json: {
        enabled: true,
        url: "https://mailent-auth.test",
        publishable_key: "sb_publishable_test",
      },
    }),
  );
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/workspace");
  await expect(
    page.getByRole("heading", { name: "Welcome to Mailent" }),
  ).toBeVisible();
  await page
    .getByLabel("Email address")
    .fill("a.long.email.address.for.layout.checks@company.example");
  await expectPageFits(page);
  const inputBox = await page.getByLabel("Email address").boundingBox();
  const cardBox = await page.locator(".sign-in-card").boundingBox();
  expect(inputBox!.x + inputBox!.width).toBeLessThan(
    cardBox!.x + cardBox!.width,
  );
  await expect(
    page.getByRole("button", { name: "Sign in", exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Email me a sign-in link" }).click();
  await expect(
    page.getByRole("button", { name: "Send sign-in link" }),
  ).toBeVisible();
  await expect(page.getByLabel("Password", { exact: true })).toHaveCount(0);
  expect(await page.getByRole("main").innerText()).not.toMatch(
    /\b(Jev|PostgreSQL|persistent|forensic)\b/i,
  );
  await page.screenshot({
    path: "test-results/sign-in-desktop.png",
    fullPage: true,
  });
  await page.getByRole("link", { name: "Privacy", exact: true }).click();
  await expect(page).toHaveURL(/\/privacy$/);
  await expect(
    page.getByRole("heading", { name: "Your data in Mailent." }),
  ).toBeVisible();
  await expect(page.getByText(/Jev, provided through Codiv/)).toBeVisible();
  await expectPageFits(page);
});

test("homepage preview, entry actions, and reduced motion work", async ({
  page,
}) => {
  test.setTimeout(90000);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  for (const width of [1280, 1920]) {
    await page.setViewportSize({ width, height: 1080 });
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(
      "Your mail.Every connection.In the clear.",
    );
    await expectPageFits(page);
    await page.getByRole("button", { name: "Capture", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "See what really happened." }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Capture", exact: true }),
    ).toHaveAttribute("aria-pressed", "true");
    await page.getByRole("button", { name: "Monitor", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Keep up with changes." }),
    ).toBeVisible();
    await page.locator(".home-final").scrollIntoViewIfNeeded();
    await expect(page.locator(".home-final")).toHaveCSS("opacity", "1");
    await expectPageFits(page);
  }
  await page.goto("/");
  await page
    .getByRole("link", { name: "Check a domain", exact: true })
    .first()
    .click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Check a domain", exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await page.reload();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.goto("/");
  await page
    .getByRole("link", { name: "Analyze a capture", exact: true })
    .first()
    .click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(
    page.getByRole("dialog").locator("input[type=file]"),
  ).toHaveCount(1);
  await page.keyboard.press("Escape");
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto("/");
  await expect(page.locator(".home-final")).toHaveCSS("opacity", "1");
  await expect(page.locator(".wire-pulse")).toHaveCSS("animation-name", "none");
  await page.setViewportSize({ width: 1440, height: 1050 });
  await page.screenshot({
    path: "test-results/homepage-desktop.png",
    fullPage: true,
  });
  await page.screenshot({ path: "test-results/homepage-hero.png" });
  expect(errors).toEqual([]);
});

test("CLI installer is available and homepage command fits", async ({
  page,
  request,
}) => {
  const script = await request.get("/install.sh");
  expect(script.ok()).toBe(true);
  const body = await script.text();
  expect(body).toMatch(/^#!\/usr\/bin\/env bash/);
  expect(body).toContain("sha256sum");
  expect(body).not.toContain("<html");
  await page.emulateMedia({ reducedMotion: "reduce" });
  for (const width of [1280, 1920]) {
    await page.setViewportSize({ width, height: 1050 });
    await page.goto("/#install");
    await expect(
      page.getByRole("button", { name: "Copy install command" }),
    ).toBeVisible();
    await expect(page.locator(".install-command code")).toHaveText(
      "curl -fsSL https://mailent.onrender.com/install.sh | bash",
    );
    await expectPageFits(page);
  }
  await page.setViewportSize({ width: 1440, height: 1050 });
  await page.screenshot({ path: "test-results/cli-install-desktop.png" });
});
