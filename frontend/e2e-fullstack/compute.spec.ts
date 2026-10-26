import { readFile } from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { signIn, trackProblems } from '../e2e/helpers.js';
import { BACKEND_LOG } from '../playwright.fullstack.config.js';

const PASSWORD = 'Correct-horse-battery-1';

/** Registers through the real API and follows the verification link from the backend log. */
async function registerVerifiedUser(request: import('@playwright/test').APIRequestContext) {
  const email = `e2e-${Date.now()}@example.com`;
  const register = await request.post('/api/auth/register', { data: { email, password: PASSWORD } });
  expect(register.status()).toBe(202);

  let link: string | undefined;
  for (let i = 0; i < 50 && !link; i++) {
    const log = await readFile(BACKEND_LOG, 'utf8').catch(() => '');
    link = log.match(new RegExp(`verification URL for ${email.replace('.', '\\.')}: (\\S+)`))?.[1];
    if (!link) await new Promise((r) => setTimeout(r, 100));
  }
  expect(link, 'verification link in backend log').toBeTruthy();
  const verify = await request.get(new URL(link!).pathname + new URL(link!).search, {
    maxRedirects: 0
  });
  expect(verify.status()).toBe(302);
  return email;
}

test('register, generate a key in the browser and compute on encrypted data', async ({ page, request }) => {
  const problems = trackProblems(page);
  const email = await registerVerifiedUser(request);

  await signIn(page, email, PASSWORD);
  await expect(page).toHaveURL(/\/heaas\/dashboard$/);

  await page.getByRole('button', { name: 'Generate encryption key' }).click();
  await expect(page.getByText('Ready')).toBeVisible({ timeout: 180_000 });

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

  expect(problems).toEqual([]);
});
