import { defineConfig, devices } from '@playwright/test';

// Full stack: the real backend (built separately; see HEAAS_BACKEND_BIN) behind
// `vite preview`, which proxies /api and sends the isolation headers. Nothing is
// mocked: keys are generated in the browser and the server computes for real.
const FRONTEND_PORT = 4174;
const BACKEND_PORT = 18081;
export const BACKEND_LOG = 'e2e-fullstack/.backend.log';

export default defineConfig({
  testDir: 'e2e-fullstack',
  outputDir: 'test-results/fullstack',
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  timeout: 240_000,
  use: {
    baseURL: `http://localhost:${FRONTEND_PORT}`,
    trace: 'retain-on-failure'
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: 'sh e2e-fullstack/start-backend.sh',
      url: `http://127.0.0.1:${BACKEND_PORT}/api/health`,
      env: { FULLSTACK_BACKEND_PORT: String(BACKEND_PORT), FULLSTACK_LOG: BACKEND_LOG },
      reuseExistingServer: false,
      timeout: 120_000
    },
    {
      command: `pnpm build && pnpm preview --port ${FRONTEND_PORT} --strictPort`,
      url: `http://localhost:${FRONTEND_PORT}/heaas/login`,
      env: { BACKEND_URL: `http://127.0.0.1:${BACKEND_PORT}` },
      reuseExistingServer: false,
      timeout: 180_000
    }
  ]
});
