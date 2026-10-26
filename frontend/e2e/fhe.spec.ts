import { expect, test, type Page, type Request } from '@playwright/test';
import { cspViolations, mockLogin, recordCspViolations, signIn, trackProblems } from './helpers.js';

// Real TFHE WASM in the browser against a mocked API. The mock cannot compute
// homomorphically, so it returns input A as the "result": decrypting it must give A
// back, which exercises keygen, encryption, serialization and decryption for real.

const KEY_ID = '7f3c2a1e-0000-4000-8000-00000000c0de';

interface Captured {
  keyUpload: Buffer | null;
  bodies: Buffer[];
  jobs: { key_id: string; operation: string; inputs: string[] }[];
  idempotencyKeys: (string | undefined)[];
}

async function mockFheApi(page: Page): Promise<Captured> {
  const captured: Captured = { keyUpload: null, bodies: [], jobs: [], idempotencyKeys: [] };
  let registered = false;
  let polls = 0;

  page.on('request', (req: Request) => {
    const body = req.postDataBuffer();
    if (body) captured.bodies.push(body);
  });

  await page.route('**/api/keys', async (route) => {
    if (route.request().method() === 'POST') {
      captured.keyUpload = route.request().postDataBuffer();
      registered = true;
      await route.fulfill({
        status: 201,
        json: {
          id: KEY_ID,
          sha256: 'ab'.repeat(32),
          size_bytes: captured.keyUpload?.length ?? 0,
          created_at: '2026-10-26T12:00:00'
        }
      });
      return;
    }
    await route.fulfill({
      json: registered
        ? [{ id: KEY_ID, sha256: 'ab'.repeat(32), size_bytes: 60_228_265, created_at: '2026-10-26T12:00:00' }]
        : []
    });
  });
  await page.route(`**/api/keys/${KEY_ID}`, async (route) => {
    registered = false;
    await route.fulfill({ status: 204, body: '' });
  });

  await page.route('**/api/compute/jobs', async (route) => {
    const job = route.request().postDataJSON() as Captured['jobs'][number];
    captured.jobs.push(job);
    captured.idempotencyKeys.push(route.request().headers()['idempotency-key']);
    polls = 0;
    await route.fulfill({
      status: 202,
      json: { id: `job-${captured.jobs.length}`, status: 'pending', error_message: null }
    });
  });
  await page.route('**/api/compute/jobs/job-*/result', async (route) => {
    // "Compute" by echoing the first input back: it decrypts to the first operand.
    await route.fulfill({
      contentType: 'application/octet-stream',
      body: Buffer.from(captured.jobs.at(-1)!.inputs[0], 'base64')
    });
  });
  await page.route('**/api/compute/jobs/job-*', async (route) => {
    polls += 1;
    await route.fulfill({
      json: { id: 'job', status: polls < 2 ? 'processing' : 'completed', error_message: null }
    });
  });
  return captured;
}

async function storedClientKey(page: Page): Promise<Buffer> {
  const bytes = await page.evaluate(
    () =>
      new Promise<number[]>((resolve, reject) => {
        const open = indexedDB.open('heaas');
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const get = open.result.transaction('client-keys').objectStore('client-keys').getAll();
          get.onsuccess = () => resolve(Array.from(get.result[0].clientKey as Uint8Array));
          get.onerror = () => reject(get.error);
        };
      })
  );
  return Buffer.from(bytes);
}

test.beforeEach(async ({ page }) => {
  await recordCspViolations(page);
});

test('keys are generated and used in the browser; only the evaluation key is uploaded', async ({ page }) => {
  test.setTimeout(180_000);
  const problems = trackProblems(page);
  await mockLogin(page);
  const captured = await mockFheApi(page);

  await signIn(page);
  await expect(page).toHaveURL(/\/heaas\/dashboard$/);
  await page.getByRole('button', { name: 'Generate encryption key' }).click();
  await expect(page.getByText('Ready')).toBeVisible({ timeout: 120_000 });

  // The upload is the ~60 MB compressed server key, not the ~31 KB client key.
  expect(captured.keyUpload?.length ?? 0).toBeGreaterThan(10_000_000);
  const clientKey = await storedClientKey(page);
  expect(clientKey.length).toBeGreaterThan(10_000);
  expect(clientKey.length).toBeLessThan(1_000_000);

  await page.getByRole('button', { name: 'Max', exact: true }).click();
  await page.getByLabel('Value A').fill('51234');
  await page.getByLabel('Value B').fill('7');
  await page.getByRole('button', { name: 'Run' }).click();

  // Decrypted in the browser: the mock echoed input A, and max(51234, 7) = 51234.
  await expect(page.getByTestId('result-value')).toHaveText('51234', { timeout: 60_000 });
  await expect(page.getByText('Matches expected')).toBeVisible();

  const [job] = captured.jobs;
  expect(job.key_id).toBe(KEY_ID);
  expect(job.operation).toBe('max');
  expect(job.inputs).toHaveLength(2);
  expect(captured.idempotencyKeys[0]).toMatch(/^[0-9a-f-]{36}$/);
  for (const input of job.inputs) {
    const bytes = Buffer.from(input, 'base64');
    expect(bytes.length).toBeGreaterThan(100_000); // a ciphertext, not a plaintext number
    expect(bytes.includes(Buffer.from('51234'))).toBe(false);
  }

  // No request body ever contains the client key's secret material.
  const secret = clientKey.subarray(clientKey.length / 2, clientKey.length / 2 + 64);
  for (const body of captured.bodies) expect(body.includes(secret)).toBe(false);

  expect(await cspViolations(page)).toEqual([]);
  expect(problems).toEqual([]);
});

test('the key survives a reload and can be deleted', async ({ page }) => {
  test.setTimeout(180_000);
  await mockLogin(page);
  await mockFheApi(page);

  await signIn(page);
  await page.getByRole('button', { name: 'Generate encryption key' }).click();
  await expect(page.getByText('Ready')).toBeVisible({ timeout: 120_000 });

  await page.reload();
  await expect(page.getByText('Ready')).toBeVisible({ timeout: 30_000 });
  await page.getByLabel('Value A').fill('300');
  await page.getByLabel('Value B').fill('300');
  await page.getByRole('button', { name: 'Run' }).click();
  // Echoed input A decrypts to 300; 300 + 300 = 600 is expected, so it must flag a mismatch.
  await expect(page.getByTestId('result-value')).toHaveText('300', { timeout: 60_000 });
  await expect(page.getByText('Does not match 600')).toBeVisible();

  await page.getByRole('button', { name: 'Delete key' }).click();
  await expect(page.getByRole('button', { name: 'Generate encryption key' })).toBeVisible();
  expect(
    await page.evaluate(
      () =>
        new Promise<number>((resolve) => {
          const open = indexedDB.open('heaas');
          open.onsuccess = () => {
            const count = open.result.transaction('client-keys').objectStore('client-keys').count();
            count.onsuccess = () => resolve(count.result);
          };
        })
    )
  ).toBe(0);
});
