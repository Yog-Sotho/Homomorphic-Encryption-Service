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

/** Mocks the auth endpoints every page may call while signed out. */
export async function mockPublicAuthApi(page: Page) {
  await page.route('**/api/auth/providers', (route) =>
    route.fulfill({ json: { google: false, github: false } })
  );
}

/**
 * Mocks a successful login and returns the signed-in user. Afterwards the
 * refresh endpoint answers as if the browser held the HttpOnly session cookie,
 * so reloads stay signed in.
 */
export async function mockLogin(page: Page) {
  const user = { id: 'u1', email: 'alice@example.com', created_at: '2026-10-25T00:00:00' };
  const session = { token: 'access-token', expires_in: 900, user };
  let signedIn = false;
  await mockPublicAuthApi(page);
  await page.route('**/api/auth/login', (route) => {
    signedIn = true;
    return route.fulfill({ json: session });
  });
  await page.route('**/api/auth/refresh', (route) =>
    signedIn
      ? route.fulfill({ json: session })
      : route.fulfill({ status: 401, json: { message: 'Not signed in' } })
  );
  return user;
}

export async function signIn(page: Page, email = 'alice@example.com', password = 'Correct-horse-1') {
  await page.goto('/heaas/login');
  await page.getByLabel('Email').fill(email);
  await page.locator('#password').fill(password);
  await page.getByRole('button', { name: 'Login' }).click();
}
