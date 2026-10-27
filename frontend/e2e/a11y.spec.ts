import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { mockLogin, mockPublicAuthApi, signIn } from './helpers.js';

// Every page is scanned with axe-core against WCAG 2.2 A/AA; no violations allowed.

const KEY = {
  id: '7f3c2a1e-0000-4000-8000-00000000c0de',
  sha256: 'ab'.repeat(32),
  size_bytes: 60_228_265,
  created_at: '2026-10-26T12:00:00'
};

async function scan(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  const summary = results.violations.map(
    (v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(' ')).join(', ')})`
  );
  expect(summary).toEqual([]);
}

async function mockSignedInApi(page: Page) {
  await mockLogin(page);
  await page.route('**/api/he/params', (route) => route.fulfill({ json: { max_keys_per_user: 2 } }));
  await page.route('**/api/keys', (route) => route.fulfill({ json: [KEY] }));
  await page.route('**/api/user/me', (route) =>
    route.fulfill({
      json: {
        id: 'u1',
        email: 'alice@example.com',
        email_verified: true,
        has_password: true,
        created_at: '2026-10-25T00:00:00',
        oauth_providers: ['github'],
        daily_usage: { count: 3, quota: 100, date: '2026-10-27' }
      }
    })
  );
  await page.route('**/api/compute/jobs?*', (route) =>
    route.fulfill({
      json: {
        data: [
          {
            id: 'job-1',
            status: 'completed',
            operation: 'multiply',
            key_id: KEY.id,
            attempts: 1,
            error_message: null,
            input_bytes: 264_000,
            result_bytes: 132_000,
            created_at: '2026-10-27T10:00:00',
            started_at: null,
            finished_at: null
          },
          {
            id: 'job-2',
            status: 'failed',
            operation: 'add',
            key_id: KEY.id,
            attempts: 3,
            error_message: 'Internal error',
            input_bytes: 264_000,
            result_bytes: null,
            created_at: '2026-10-27T09:00:00',
            started_at: null,
            finished_at: null
          }
        ],
        next_cursor: 'next'
      }
    })
  );
}

test('sign-in, registration and password pages', async ({ page }) => {
  await mockPublicAuthApi(page);
  await page.goto('/heaas/login');
  await expect(page.getByRole('heading', { name: 'HE SaaS Login' })).toBeVisible();
  await scan(page);
  await page.getByRole('button', { name: 'Register' }).click();
  await page.locator('#password').fill('weak');
  await scan(page);
  await page.goto('/heaas/reset#token=t');
  await expect(page.getByRole('heading', { name: 'Choose a new password' })).toBeVisible();
  await scan(page);
  await page.goto('/heaas/verify');
  await expect(page.getByRole('alert')).toBeVisible();
  await scan(page);
});

test('signed-in pages', async ({ page }) => {
  await mockSignedInApi(page);
  await signIn(page);

  // No key in this browser yet.
  await expect(page.getByRole('link', { name: 'Import a key' })).toBeVisible();
  await scan(page);

  // With a stored (sealed) key, the dashboard asks for its passphrase.
  await page.evaluate(
    (keyId) =>
      new Promise<void>((resolve) => {
        const open = indexedDB.open('heaas', 1);
        open.onupgradeneeded = () => open.result.createObjectStore('client-keys', { keyPath: 'keyId' });
        open.onsuccess = () => {
          const tx = open.result.transaction('client-keys', 'readwrite');
          tx.objectStore('client-keys').put({
            keyId,
            serverKeySha256: 'ab'.repeat(32),
            createdAt: '2026-10-26T12:00:00Z',
            sealed: { v: 1, kdf: 'PBKDF2-SHA256', iterations: 600000, salt: 'AA==', iv: 'AA==', ciphertext: 'AA==' }
          });
          tx.oncomplete = () => resolve();
        };
      }),
    KEY.id
  );
  await page.reload();
  await expect(page.getByText('Enter your passphrase')).toBeVisible();
  await scan(page);

  await page.getByRole('link', { name: 'Keys', exact: true }).click();
  await expect(page.getByTestId('key-entry')).toBeVisible();
  await scan(page);
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await scan(page);

  await page.getByRole('link', { name: 'Jobs', exact: true }).click();
  await expect(page.getByTestId('job-row').first()).toBeVisible();
  await scan(page);

  await page.getByRole('link', { name: 'Account' }).click();
  await expect(page.getByRole('heading', { name: 'Profile' })).toBeVisible();
  await scan(page);
});
