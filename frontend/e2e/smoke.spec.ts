import { expect, test } from '@playwright/test';
import {
  cspViolations,
  mockLogin,
  mockPublicAuthApi,
  recordCspViolations,
  signIn,
  trackProblems
} from './helpers.js';

test.beforeEach(async ({ page }) => {
  await recordCspViolations(page);
});

test('login page is served with a CSP header and hydrates without violations', async ({ page }) => {
  const problems = trackProblems(page);
  await mockPublicAuthApi(page);
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
  await mockPublicAuthApi(page);
  await page.route('**/api/auth/login', (route) =>
    route.fulfill({ status: 401, json: { message: 'Invalid credentials' } })
  );

  await page.goto('/heaas/login');
  await page.getByLabel('Email').fill('alice@example.com');
  await page.locator('#password').fill('wrong-password');
  await page.getByRole('button', { name: 'Login' }).click();

  await expect(page.getByRole('alert')).toHaveText('Invalid credentials');
});

test('OAuth sign-in is completed by exchanging the one-time code', async ({ page }) => {
  const problems = trackProblems(page);
  await mockLogin(page);
  await page.route('**/api/keys', (route) => route.fulfill({ json: [] }));
  let exchanged = '';
  await page.route('**/api/auth/exchange', async (route) => {
    exchanged = (route.request().postDataJSON() as { code: string }).code;
    const user = { id: 'u1', email: 'alice@example.com', created_at: '2026-10-25T00:00:00' };
    await route.fulfill({ json: { token: 'access-token', expires_in: 900, user } });
  });

  await page.goto('/heaas/login#code=one-time-code');

  await expect(page).toHaveURL(/\/heaas\/dashboard$/);
  expect(exchanged).toBe('one-time-code');
  expect(problems).toEqual([]);
});

test('OAuth errors are shown and the fragment is cleared', async ({ page }) => {
  await mockPublicAuthApi(page);
  await page.goto('/heaas/login#error=Sign-in%20was%20cancelled.');
  await expect(page.getByRole('alert')).toHaveText('Sign-in was cancelled.');
  await expect(page).toHaveURL(/\/heaas\/login$/);
});

test('verification links sign the user in without the token reaching the server in a URL', async ({ page }) => {
  await mockLogin(page);
  await page.route('**/api/keys', (route) => route.fulfill({ json: [] }));
  const urls: string[] = [];
  page.on('request', (r) => urls.push(r.url()));
  let posted = '';
  await page.route('**/api/auth/verify', async (route) => {
    posted = (route.request().postDataJSON() as { token: string }).token;
    const user = { id: 'u1', email: 'alice@example.com', created_at: '2026-10-25T00:00:00' };
    await route.fulfill({ json: { token: 'access-token', expires_in: 900, user } });
  });

  await page.goto('/heaas/verify#token=secret-verify-token');

  await expect(page).toHaveURL(/\/heaas\/dashboard$/);
  expect(posted).toBe('secret-verify-token');
  expect(urls.some((u) => u.includes('secret-verify-token'))).toBe(false);
});

test('password reset pages post the token from the fragment', async ({ page }) => {
  let body: { token?: string; new_password?: string } = {};
  await page.route('**/api/auth/reset-password', async (route) => {
    body = route.request().postDataJSON();
    await route.fulfill({ json: { message: 'Password reset. You can now sign in.' } });
  });

  await page.goto('/heaas/reset#token=reset-token');
  await expect(page).toHaveURL(/\/heaas\/reset$/);
  await page.getByLabel('New password').fill('Brand-New-Pass-7');
  await page.getByLabel('Repeat it').fill('Brand-New-Pass-7');
  await page.getByRole('button', { name: 'Set password' }).click();

  await expect(page.getByRole('status')).toContainText('Password reset');
  expect(body).toEqual({ token: 'reset-token', new_password: 'Brand-New-Pass-7' });
});
