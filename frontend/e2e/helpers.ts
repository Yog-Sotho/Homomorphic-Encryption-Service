import type { Page } from '@playwright/test';

/** Collects console errors and uncaught exceptions for a page. */
export function trackProblems(page: Page): string[] {
  const problems: string[] = [];
  page.on('console', (msg) => {
    if (msg.type() === 'error') problems.push(`console: ${msg.text()}`);
  });
  page.on('pageerror', (err) => problems.push(`pageerror: ${err.message}`));
  return problems;
}

/** Records CSP violations into `window.__csp`; call before navigating. */
export async function recordCspViolations(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const store: string[] = [];
    (window as unknown as { __csp: string[] }).__csp = store;
    document.addEventListener('securitypolicyviolation', (e) =>
      store.push(`${e.violatedDirective} ${e.blockedURI}`)
    );
  });
}

export async function cspViolations(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __csp?: string[] }).__csp ?? []);
}

/** Mocks a successful login and returns the signed-in user. */
export async function mockLogin(page: Page) {
  const user = { id: 'u1', email: 'alice@example.com', created_at: '2026-10-25T00:00:00' };
  // Payload of the access token only needs a future `exp` for the layout's expiry check.
  const exp = Math.floor(Date.now() / 1000) + 3600;
  const token = `h.${Buffer.from(JSON.stringify({ sub: 'u1', exp })).toString('base64url')}.s`;
  await page.route('**/api/auth/login', (route) =>
    route.fulfill({ json: { token, refresh_token: 'r1', user } })
  );
  return user;
}

/** Signs in through the login form (with whatever API the test has mocked or started). */
export async function signIn(page: Page, email = 'alice@example.com', password = 'Correct-horse-1') {
  await page.goto('/heaas/login');
  await page.getByLabel('Email').fill(email);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Login' }).click();
}
