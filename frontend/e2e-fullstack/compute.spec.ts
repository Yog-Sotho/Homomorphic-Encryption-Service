import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { signIn, trackProblems } from '../e2e/helpers.js';
import { BACKEND_LOG } from '../playwright.fullstack.config.js';

const PASSWORD = 'Correct-horse-battery-1';
const KEY_PASSPHRASE = 'quiet-meadow-lantern-9';

/**
 * Registers through the real API and returns the verification link the backend
 * logged (SMTP is not configured in this suite).
 */
async function register(request: import('@playwright/test').APIRequestContext) {
  const email = `e2e-${Date.now()}@example.com`;
  const response = await request.post('/api/auth/register', { data: { email, password: PASSWORD } });
  expect(response.status()).toBe(202);

  let link: string | undefined;
  for (let i = 0; i < 50 && !link; i++) {
    const log = await readFile(BACKEND_LOG, 'utf8').catch(() => '');
    link = log.match(new RegExp(`for ${email.replace('.', '\\.')}: (\\S+)`))?.[1];
    if (!link) await new Promise((r) => setTimeout(r, 100));
  }
  expect(link, 'verification link in backend log').toMatch(/\/heaas\/verify#token=/);
  return { email, link: link! };
}

test('register, generate a key in the browser and compute on encrypted data', async ({ page, request }) => {
  const problems = trackProblems(page);
  const { email, link } = await register(request);

  // Following the emailed link verifies the address and signs in.
  await page.goto(link);
  await expect(page).toHaveURL(/\/heaas\/dashboard$/);
  // The session survives a reload through the HttpOnly refresh cookie alone.
  await page.reload();
  await expect(page).toHaveURL(/\/heaas\/dashboard$/);
  await expect(page.locator('.user-chip')).toHaveText(email);
  const scriptVisible = await page.evaluate(() => document.cookie);
  expect(scriptVisible).not.toContain('heaas_refresh');

  // The key pair is made in the browser and its secret half sealed with a passphrase.
  await page.getByRole('link', { name: 'Keys', exact: true }).click();
  await page.getByLabel('Passphrase', { exact: true }).fill(KEY_PASSPHRASE);
  await page.getByLabel('Repeat the passphrase').fill(KEY_PASSPHRASE);
  await page.getByRole('button', { name: 'Generate encryption key' }).click();
  await expect(page.getByTestId('key-entry').getByText('Unlocked')).toBeVisible({ timeout: 180_000 });
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click();
  await expect(page.getByText('Ready')).toBeVisible();

  // 300 × 300 = 90000 ≡ 24464 (mod 65536): computed by the server on ciphertexts.
  await page.getByRole('button', { name: 'Multiply', exact: true }).click();
  await page.getByLabel('Value A').fill('300');
  await page.getByLabel('Value B').fill('300');
  await page.getByRole('button', { name: 'Run' }).click();
  await expect(page.getByTestId('result-value')).toHaveText('24464', { timeout: 120_000 });
  await expect(page.getByText('Matches expected')).toBeVisible();

  // A second operation reuses the cached server key.
  await page.getByRole('button', { name: 'Subtract', exact: true }).click();
  await page.getByLabel('Value A').fill('3');
  await page.getByLabel('Value B').fill('10');
  await page.getByRole('button', { name: 'Run' }).click();
  await expect(page.getByTestId('result-value')).toHaveText('65529', { timeout: 120_000 });
  await expect(page.getByText('Matches expected')).toBeVisible();

  // The server keeps both results; the jobs page decrypts them here.
  await page.getByRole('link', { name: 'Jobs', exact: true }).click();
  await expect(page.getByTestId('job-row')).toHaveCount(2);
  for (const row of await page.getByTestId('job-row').all()) {
    await row.getByRole('button', { name: 'Decrypt' }).click();
  }
  await expect(page.getByTestId('job-value')).toHaveText(['65529', '24464'], { timeout: 30_000 });

  // After a reload the key must be unlocked again.
  await page.goto('/heaas/dashboard');
  await page.getByLabel('Passphrase').fill(KEY_PASSPHRASE);
  await page.getByRole('button', { name: 'Unlock key' }).click();
  await expect(page.getByText('Ready')).toBeVisible({ timeout: 30_000 });

  // Signing out ends the session for good: a reload goes back to sign-in.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page).toHaveURL(/\/heaas\/login$/);
  await page.goto('/heaas/dashboard');
  await expect(page).toHaveURL(/\/heaas\/login$/);

  // Password sign-in works for the verified account.
  await signIn(page, email, PASSWORD);
  await expect(page).toHaveURL(/\/heaas\/dashboard$/);

  expect(problems.filter((p) => !p.includes('401'))).toEqual([]);
});
