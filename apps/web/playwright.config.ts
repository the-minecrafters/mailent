import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:5174",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  webServer: [
    {
      command: "cargo run --manifest-path ../../Cargo.toml -p mailent-core",
      url: "http://127.0.0.1:18080/ready",
      env: {
        MAILENT_CORE_HOST: "127.0.0.1",
        MAILENT_CORE_PORT: "18080",
        MAILENT_JEV_ENABLED: "false",
        CARGO_INCREMENTAL: "0",
      },
      timeout: 120000,
      reuseExistingServer: false,
    },
    {
      command: "pnpm dev --port 5174 --strictPort",
      url: "http://127.0.0.1:5174",
      env: { MAILENT_CORE_PROXY_TARGET: "http://127.0.0.1:18080" },
      reuseExistingServer: false,
    },
  ],
});
