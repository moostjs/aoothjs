// Boot sequence:
//
//   # In one terminal:
//   DEMO_MODE=test SEED=true pnpm dev
//   # In another:
//   pnpm test:e2e
//
// The dev server is intentionally NOT spun up by Playwright — keeping the two
// processes separate makes it trivial to inspect logs / attach a debugger.

import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "test-e2e",
  retries: 0,
  // Serial until `POST /__test/reset` is bulletproof under contention — see
  // USER_STORIES.md §2.4. Bump once specs land and we measure per-spec reset
  // throughput against a real run.
  workers: 1,
  reporter: "list",
  use: {
    baseURL: process.env.BASE_URL ?? "http://localhost:3001",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
