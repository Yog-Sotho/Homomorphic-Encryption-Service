import { expect, test, type Page } from '@playwright/test';

/** Collects console errors, uncaught exceptions and CSP violations for a page. */
function trackProblems(page: Page): string[] {
  const problems: string[] = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') problems.push(`console: ${msg.text()}`);
  });
  page.on('pageerror', (err) => problems.push(`pageerror: ${err.message}`));
  return problems;
}

async function cspViolations(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __csp?: string[] }).__csp ?? []);
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    const store: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = store;
    document.addEventListener('securitypolicyviolation', (e) =>
      store.push(`${e.violatedDirective} ${e.blockedURI}`)
    );
  });
});

test('login page is served with a CSP header and hydrates without violations', async ({ page }) => {
  const problems = trackProblems(page);
  const response = await page.goto('/heaas/login');

  expect(response?.status()).toBe(200);
  const csp = response?.headers()['content-security-policy'] ?? '';
  const scriptSrc = csp.split(';').find((d) => d.trim().startsWith('script-src')) ?? '';
  expect(scriptSrc).toContain("'self'");
  expect(scriptSrc).toMatch(/'sha256-/);
  expect(scriptSrc).not.toMatch(/unsafe-inline|unsafe-eval/);

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

test('signing in reaches the dashboard and runs a computation', async ({ page }) => {
  const problems = trackProblems(page);
  const user = { id: 'u1', email: 'alice@example.com', created_at: '2026-10-25T00:00:00' };
  // Payload of the access token only needs a future `exp` for the layout's expiry check.
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const token = `h.${Buffer.from(JSON.stringify({ sub: 'u1', exp })).toString('base64url')}.s`;

  await page.route('**/api/auth/login', (route) =>
    route.fulfill({ json: { token, refresh_token: 'r1', user } })
  );
  await page.route('**/api/compute/sandbox', async (route) => {
    const body = route.request().postDataJSON() as { value1: number; value2: number };
    await route.fulfill({
      json: { plaintext_result: body.value1 + body.value2, result_b64: 'Y2lwaGVydGV4dA==' }
    });
  });

  await page.goto('/heaas/login');
  await page.getByLabel('Email').fill(user.email);
  await page.locator('#password').fill('Correct-horse-1');
  await page.getByRole('button', { name: 'Login' }).click();

  await expect(page).toHaveURL(/\/heaas\/dashboard$/);
  // The app shell (hidden on /login) must appear after client-side navigation.
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await page.getByLabel('Value A').fill('10');
  await page.getByLabel('Value B').fill('5');
  await page.getByRole('button', { name: 'Run' }).click();

  await expect(page.locator('.result-number')).toHaveText('15');
  await expect(page.getByText('Verified Match')).toBeVisible();
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
