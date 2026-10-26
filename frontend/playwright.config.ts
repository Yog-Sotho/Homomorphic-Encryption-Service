import { defineConfig, devices } from '@playwright/test';

const PORT = 4180;

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: `http://localhost:${PORT}`,
    trace: 'retain-on-failure'
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  // Serve the production build (adapter-node) so CSP and hydration match deployment.
  webServer: {
    command: `pnpm build && PORT=${PORT} node server.js`,
    url: `http://localhost:${PORT}/heaas/login`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000
  }
});
