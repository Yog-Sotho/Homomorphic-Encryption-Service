import { expect, test } from '@playwright/test';
import { cspViolations, mockLogin, recordCspViolations, signIn, trackProblems } from './helpers.js';

test.beforeEach(async ({ page }) => {
  await recordCspViolations(page);
});

test('login page is served with a CSP header and hydrates without violations', async ({ page }) => {
  const problems = trackProblems(page);
  const response = await page.goto('/heaas/login');

  expect(response?.status()).toBe(200);
  const csp = response?.headers()['content-security-policy'] ?? '';
  const scriptSrc = csp.split(';').find((d) => d.trim().startsWith('script-src')) ?? '';
  expect(scriptSrc).toContain("'self'");
  expect(scriptSrc).toMatch(/'sha256-/);
  // 'wasm-unsafe-eval' only allows compiling WebAssembly; JS eval stays blocked.
  expect(scriptSrc).toContain("'wasm-unsafe-eval'");
  expect(scriptSrc).not.toMatch(/'unsafe-inline'|'unsafe-eval'/);
  // TFHE's WASM needs SharedArrayBuffer, which requires cross-origin isolation.
  expect(response?.headers()['cross-origin-opener-policy']).toBe('same-origin');
  expect(response?.headers()['cross-origin-embedder-policy']).toBe('require-corp');
  expect(await page.evaluate(() => crossOriginIsolated)).toBe(true);

  await expect(page.getByRole('heading', { name: 'HE SaaS Login' })).toBeVisible();
  // Only works once Svelte has hydrated the page.
  await page.getByRole('button', { name: 'Register' }).click();
  await expect(page.getByRole('heading', { name: 'Create an Account' })).toBeVisible();

  expect(await cspViolations(page)).toEqual([]);
  expect(problems).toEqual([]);
});

test('root redirects to login without a session', async ({ page }) => {
  await page.goto('/heaas');
  await expect(page).toHaveURL(/\/heaas\/login$/);
});

test('signing in reaches the dashboard', async ({ page }) => {
  const problems = trackProblems(page);
  await mockLogin(page);
  await page.route('**/api/keys', (route) => route.fulfill({ json: [] }));

  await signIn(page);

  await expect(page).toHaveURL(/\/heaas\/dashboard$/);
  // The app shell (hidden on /login) must appear after client-side navigation.
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Generate encryption key' })).toBeVisible();
  expect(await cspViolations(page)).toEqual([]);
  expect(problems).toEqual([]);
});

test('API errors are shown to the user', async ({ page }) => {
  await page.route('**/api/auth/login', (route) =>
    route.fulfill({ status: 401, json: { message: 'Invalid credentials' } })
  );

  await page.goto('/heaas/login');
  await page.getByLabel('Email').fill('alice@example.com');
  await page.locator('#password').fill('wrong-password');
  await page.getByRole('button', { name: 'Login' }).click();

  await expect(page.getByRole('alert')).toHaveText('Invalid credentials');
});
