import { createHash } from 'node:crypto';
import { expect, test, type Page, type Request } from '@playwright/test';
import { cspViolations, mockLogin, recordCspViolations, signIn, trackProblems } from './helpers.js';

// Real TFHE WASM in the browser against a mocked API. The mock cannot compute
// homomorphically, so it returns input A as the "result": decrypting it must give A
// back, which exercises keygen, encryption, serialization and decryption for real.

const KEY_ID = '7f3c2a1e-0000-4000-8000-00000000c0de';
const PASSPHRASE = 'tidy-lantern-orbit-42';

interface Captured {
  keyUpload: Buffer | null;
  publicKeyUpload: Buffer | null;
  bodies: Buffer[];
  jobs: {
    key_id: string;
    operation: string;
    integer_type: string;
    inputs: string[];
    scalar?: string;
    program?: { steps: { op: string; args: unknown[] }[]; outputs?: number[] };
  }[];
  idempotencyKeys: (string | undefined)[];
}

async function mockFheApi(page: Page): Promise<Captured> {
  const captured: Captured = {
    keyUpload: null,
    publicKeyUpload: null,
    bodies: [],
    jobs: [],
    idempotencyKeys: []
  };
  let registered: {
    id: string;
    sha256: string;
    size_bytes: number;
    created_at: string;
    supports_proofs: boolean;
    has_public_key: boolean;
  } | null = null;
  let polls = 0;

  page.on('request', (req: Request) => {
    const body = req.postDataBuffer();
    if (body) captured.bodies.push(body);
  });

  await page.route('**/api/v1/he/params', (route) => route.fulfill({ json: { max_keys_per_user: 2 } }));
  await page.route('**/api/v1/keys', async (route) => {
    if (route.request().method() === 'POST') {
      const body = route.request().postDataBuffer() ?? Buffer.alloc(0);
      captured.keyUpload = body;
      // Like the server: the key's id and the SHA-256 of what was uploaded.
      registered = {
        id: KEY_ID,
        sha256: createHash('sha256').update(body).digest('hex'),
        size_bytes: body.length,
        created_at: '2026-10-26T12:00:00',
        supports_proofs: true,
        has_public_key: false
      };
      await route.fulfill({ status: 201, json: registered });
      return;
    }
    await route.fulfill({ json: registered ? [registered] : [] });
  });
  await page.route(`**/api/v1/keys/${KEY_ID}`, async (route) => {
    registered = null;
    await route.fulfill({ status: 204, body: '' });
  });
  await page.route(`**/api/v1/keys/${KEY_ID}/public-key`, async (route) => {
    captured.publicKeyUpload = route.request().postDataBuffer();
    registered = registered && { ...registered, has_public_key: true };
    await route.fulfill({ json: registered });
  });

  // The mock echoes input N back as result N, so results have the input type.
  const shape = (i: number) => ({
    integer_type: captured.jobs[i].integer_type,
    result_type: captured.jobs[i].integer_type,
    result_types: (captured.jobs[i].program?.outputs ?? [0]).map(() => captured.jobs[i].integer_type),
    compressed_results: false,
    input_count: captured.jobs[i].inputs.length,
    proven: false,
    scalar: captured.jobs[i].scalar ?? null,
    program: captured.jobs[i].program ?? null
  });

  const summary = (i: number) => ({
    id: `job-${i + 1}`,
    status: 'completed',
    operation: captured.jobs[i].operation,
    ...shape(i),
    key_id: KEY_ID,
    attempts: 1,
    error_message: null,
    input_bytes: 264_000,
    result_bytes: 132_000,
    created_at: '2026-10-27T10:00:00',
    started_at: null,
    finished_at: null
  });
  await page.route('**/api/v1/compute/jobs', async (route) => {
    const job = route.request().postDataJSON() as Captured['jobs'][number];
    captured.jobs.push(job);
    captured.idempotencyKeys.push(route.request().headers()['idempotency-key']);
    polls = 0;
    await route.fulfill({
      status: 202,
      json: { id: `job-${captured.jobs.length}`, status: 'pending', error_message: null }
    });
  });
  await page.route('**/api/v1/compute/jobs?*', (route) =>
    route.fulfill({ json: { data: captured.jobs.map((_, i) => summary(i)).reverse(), next_cursor: null } })
  );
  await page.route('**/api/v1/compute/jobs/job-*/result*', async (route) => {
    const url = new URL(route.request().url());
    const index = Number(/job-(\d+)/.exec(url.pathname)![1]) - 1;
    const output = Number(url.searchParams.get('output') ?? 0);
    // "Compute" by echoing input N back as result N: it decrypts to operand N.
    await route.fulfill({
      contentType: 'application/octet-stream',
      body: Buffer.from(captured.jobs[index].inputs[output], 'base64')
    });
  });
  await page.route('**/api/v1/compute/jobs/job-*', async (route) => {
    if (route.request().method() === 'DELETE') {
      await route.fulfill({ status: 204, body: '' });
      return;
    }
    polls += 1;
    await route.fulfill({
      json: {
        id: 'job',
        status: polls < 2 ? 'processing' : 'completed',
        error_message: null,
        ...shape(captured.jobs.length - 1)
      }
    });
  });
  return captured;
}

interface StoredRecord {
  keyId: string;
  serverKeySha256?: string;
  clientKey?: unknown;
  sealed?: { iterations: number; salt: string; iv: string; ciphertext: string };
}

async function storedRecords(page: Page): Promise<StoredRecord[]> {
  return page.evaluate(
    () =>
      new Promise<StoredRecord[]>((resolve, reject) => {
        const open = indexedDB.open('heaas');
        open.onerror = () => reject(open.error);
        open.onsuccess = () => {
          const all = open.result.transaction('client-keys').objectStore('client-keys').getAll();
          all.onsuccess = () => resolve(all.result as StoredRecord[]);
          all.onerror = () => reject(all.error);
        };
      })
  );
}

/**
 * Opens the stored key with WebCrypto in the page, independently of the app's
 * code: PBKDF2-SHA256 → AES-256-GCM, bound to the server key's SHA-256.
 */
async function openStoredKey(page: Page, passphrase: string): Promise<Buffer> {
  const bytes = await page.evaluate(async (pass) => {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const open = indexedDB.open('heaas');
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    });
    const [record] = await new Promise<StoredRecord[]>((resolve) => {
      const all = db.transaction('client-keys').objectStore('client-keys').getAll();
      all.onsuccess = () => resolve(all.result as StoredRecord[]);
    });
    const sealed = record.sealed!;
    const b64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    const enc = new TextEncoder();
    const material = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: b64(sealed.salt), iterations: sealed.iterations },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: b64(sealed.iv),
        additionalData: enc.encode(`heaas-client-key/v1\0${record.serverKeySha256}`)
      },
      key,
      b64(sealed.ciphertext)
    );
    return Array.from(new Uint8Array(plain));
  }, passphrase);
  return Buffer.from(bytes);
}

/** Creates a key on the Keys page and waits until it is unlocked. */
async function createKey(page: Page) {
  await page.getByRole('link', { name: 'Keys', exact: true }).click();
  await expect(page).toHaveURL(/\/heaas\/keys$/);
  await page.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE);
  await page.getByLabel('Repeat the passphrase').fill(PASSPHRASE);
  await page.getByRole('button', { name: 'Generate encryption key' }).click();
  await expect(page.getByTestId('key-entry').getByText('Unlocked')).toBeVisible({ timeout: 120_000 });
}

async function run(page: Page, op: string, a: string, b: string, options: { type?: string; scalar?: boolean } = {}) {
  if (options.type) await page.getByLabel('Type').selectOption(options.type);
  await page.getByRole('button', { name: op, exact: true }).click();
  await page.getByLabel('Value A').fill(a);
  await page.getByLabel('Value B').fill(b);
  await page.getByLabel('Send B unencrypted').setChecked(options.scalar ?? false);
  await page.getByRole('button', { name: 'Run' }).click();
}

test.beforeEach(async ({ page }) => {
  await recordCspViolations(page);
});

test('keys are made and sealed in the browser; only the evaluation key is uploaded', async ({ page }) => {
  test.setTimeout(240_000);
  const problems = trackProblems(page);
  await mockLogin(page);
  const captured = await mockFheApi(page);

  await signIn(page);
  await expect(page).toHaveURL(/\/heaas\/dashboard$/);
  await createKey(page);

  // The upload is the ~60 MB compressed server key, not the ~48 KB client key,
  // and then the ~33 KB compact public key proofs are checked against.
  expect(captured.keyUpload?.length ?? 0).toBeGreaterThan(10_000_000);
  expect(captured.publicKeyUpload?.length ?? 0).toBeGreaterThan(10_000);
  expect(captured.publicKeyUpload?.length ?? 0).toBeLessThan(1_000_000);
  // Stored sealed under the passphrase only, with OWASP's PBKDF2 work factor.
  const [record] = await storedRecords(page);
  expect(record.keyId).toBe(KEY_ID);
  expect(record.clientKey).toBeUndefined();
  expect(record.sealed?.iterations).toBe(600_000);
  const clientKey = await openStoredKey(page, PASSPHRASE);
  expect(clientKey.length).toBeGreaterThan(10_000);
  expect(clientKey.length).toBeLessThan(1_000_000);

  // The unlocked key carries over to the dashboard (no second unlock).
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click();
  await expect(page.getByText('Ready')).toBeVisible();
  await run(page, 'Max', '51234', '7');

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

  // A 64-bit signed value beyond JavaScript's safe integers, and a plain operand:
  // min(A, 5) = A, which is what the mock echoes.
  const big = '-9007199254740993';
  await run(page, 'Min', big, '5', { type: 'i64', scalar: true });
  await expect(page.getByTestId('result-value')).toHaveText(big, { timeout: 60_000 });
  await expect(page.getByText('Matches expected')).toBeVisible();
  const second = captured.jobs[1];
  expect(second).toMatchObject({ operation: 'min', integer_type: 'i64', scalar: '5' });
  expect(second.inputs).toHaveLength(1);
  expect(Buffer.from(second.inputs[0], 'base64').length).toBeGreaterThan(400_000); // FheInt64

  // An expression with two results: compiled in the browser and sent as
  // program steps. max(a, b) with a > b is a, then b: what the mock echoes.
  await page.getByLabel('Type').selectOption('u8');
  await page.getByRole('button', { name: 'Expression', exact: true }).click();
  await page.getByLabel('Expression').fill('a +');
  await expect(page.getByText('The expression ends too early')).toBeVisible();
  await page.getByLabel('Expression').fill('lookup(a, [1, 2]');
  await expect(page.getByText("Expected ',' at position 17")).toBeVisible();
  await page.getByLabel('Expression').fill('max(a, b), b');
  await expect(page.getByText('2 results (u8, u8)')).toBeVisible();
  await page.getByLabel(/^Values for a, b/).fill('200, 3');
  await page.getByRole('button', { name: 'Run' }).click();
  await expect(page.getByTestId('result-value')).toHaveText('200, 3', { timeout: 60_000 });
  await expect(page.getByText('Matches expected')).toBeVisible();
  const third = captured.jobs[2];
  expect(third.operation).toBe('program');
  expect(third.program?.steps).toEqual([
    { op: 'max', args: [{ input: 0 }, { input: 1 }] },
    { op: 'add', args: [{ input: 1 }, { const: '0' }] }
  ]);
  expect(third.program?.outputs).toEqual([0, 1]);
  expect(third.inputs).toHaveLength(2);

  // The jobs page decrypts stored results too, each as its type.
  await page.getByRole('link', { name: 'Jobs', exact: true }).click();
  await expect(page.getByTestId('job-row')).toHaveCount(3);
  await expect(page.getByTestId('job-row').first()).toContainText('max(a, b), b + 0 (u8, 2 inputs)');
  for (const row of await page.getByTestId('job-row').all()) {
    await row.getByRole('button', { name: 'Decrypt' }).click();
  }
  await expect(page.getByTestId('job-value')).toHaveText(['200, 3', big, '51234'], { timeout: 30_000 });

  // No request body ever contains the client key or the passphrase.
  const secret = clientKey.subarray(clientKey.length / 2, clientKey.length / 2 + 64);
  for (const body of captured.bodies) {
    expect(body.includes(secret)).toBe(false);
    expect(body.includes(Buffer.from(PASSPHRASE))).toBe(false);
  }

  expect(await cspViolations(page)).toEqual([]);
  expect(problems).toEqual([]);
});

test('a reload needs the passphrase; keys can be backed up, restored and deleted', async ({ page }) => {
  test.setTimeout(240_000);
  await mockLogin(page);
  await mockFheApi(page);

  await signIn(page);
  await createKey(page);

  // Export a backup (the sealed key; no passphrase needed).
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Export backup' }).click()
  ]);
  expect(download.suggestedFilename()).toBe('heaas-key-7f3c2a1e.json');
  const backup = await (await download.createReadStream()).toArray().then((c) => Buffer.concat(c));
  expect(JSON.parse(backup.toString())).toMatchObject({ format: 'heaas-client-key', keyId: KEY_ID });

  // After a reload the key is locked; a wrong passphrase is refused.
  await page.goto('/heaas/dashboard');
  await page.getByLabel('Passphrase').fill('not-the-passphrase');
  await page.getByRole('button', { name: 'Unlock key' }).click();
  await expect(page.getByRole('alert')).toHaveText('Wrong passphrase.');
  await page.getByLabel('Passphrase').fill(PASSPHRASE);
  await page.getByRole('button', { name: 'Unlock key' }).click();
  await expect(page.getByText('Ready')).toBeVisible({ timeout: 30_000 });
  await run(page, 'Add', '300', '300');
  // Echoed input A decrypts to 300; 300 + 300 = 600 is expected, so it must flag a mismatch.
  await expect(page.getByTestId('result-value')).toHaveText('300', { timeout: 60_000 });
  await expect(page.getByText('Does not match 600')).toBeVisible();

  // A browser without the key (site data cleared) restores it from the backup.
  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        const open = indexedDB.open('heaas');
        open.onsuccess = () => {
          const tx = open.result.transaction('client-keys', 'readwrite');
          tx.objectStore('client-keys').clear();
          tx.oncomplete = () => resolve();
        };
      })
  );
  await page.goto('/heaas/keys');
  const entry = page.getByTestId('key-entry');
  await expect(entry.getByText('Not in this browser')).toBeVisible();
  await entry.getByRole('button', { name: 'Import backup' }).click();
  await entry.getByLabel('Key backup file').setInputFiles({
    name: 'heaas-key-7f3c2a1e.json',
    mimeType: 'application/json',
    buffer: backup
  });
  await entry.getByLabel('Its passphrase').fill(PASSPHRASE);
  await entry.getByRole('button', { name: 'Import', exact: true }).click();
  await expect(entry.getByText('Unlocked')).toBeVisible({ timeout: 30_000 });
  expect((await openStoredKey(page, PASSPHRASE)).length).toBeGreaterThan(10_000);

  await entry.getByRole('button', { name: 'Delete', exact: true }).click();
  await entry.getByRole('button', { name: 'Delete key' }).click();
  await expect(page.getByText('No keys yet.')).toBeVisible();
  expect(await storedRecords(page)).toEqual([]);
});

test('keys stored before passphrases are protected when next unlocked', async ({ page }) => {
  test.setTimeout(240_000);
  await mockLogin(page);
  await mockFheApi(page);
  await signIn(page);
  await createKey(page);

  // Turn the stored key back into the old, unprotected format.
  const raw = await openStoredKey(page, PASSPHRASE);
  await page.evaluate(
    (bytes) =>
      new Promise<void>((resolve) => {
        const open = indexedDB.open('heaas');
        open.onsuccess = () => {
          const tx = open.result.transaction('client-keys', 'readwrite');
          tx.objectStore('client-keys').put({
            keyId: '7f3c2a1e-0000-4000-8000-00000000c0de',
            clientKey: new Uint8Array(bytes),
            createdAt: '2026-10-01T00:00:00Z'
          });
          tx.oncomplete = () => resolve();
        };
      }),
    Array.from(raw)
  );

  await page.goto('/heaas/dashboard');
  await expect(page.getByText('is not protected')).toBeVisible();
  const newPassphrase = 'brand-new-passphrase-7';
  await page.getByLabel('New passphrase').fill(newPassphrase);
  await page.getByLabel('Repeat the passphrase').fill(newPassphrase);
  await page.getByRole('button', { name: 'Protect and unlock' }).click();
  await expect(page.getByText('Ready')).toBeVisible({ timeout: 30_000 });

  const [record] = await storedRecords(page);
  expect(record.clientKey).toBeUndefined();
  expect((await openStoredKey(page, newPassphrase)).equals(raw)).toBe(true);
});
