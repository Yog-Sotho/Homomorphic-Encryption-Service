<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { resolve } from '$app/paths';
  import { compute, errorMessage, type JobSummary, type Operation } from '#lib/api.js';
  import UnlockForm from '#lib/components/UnlockForm.svelte';
  import { bytesToBase64 } from '#lib/fhe/encoding.js';
  import type { StoredClientKey } from '#lib/fhe/keystore.js';
  import { OPERATIONS, UINT16_MAX, expectedResult, isUint16 } from '#lib/fhe/operations.js';
  import { fheSession, loadKeyOverview, type KeyEntry, type KeyOverview } from '#lib/fhe/session.svelte.js';

  const POLL_INTERVAL_MS = 750;
  const JOB_TIMEOUT_MS = 120_000;

  type Step = 'encrypting' | 'submitting' | 'computing' | 'decrypting';
  type LocalEntry = KeyEntry & { local: StoredClientKey };

  let overview = $state<KeyOverview | null>(null);
  let loadError = $state('');
  let chosenKeyId = $state('');

  let val1 = $state(10);
  let val2 = $state(5);
  let operation = $state<Operation>('add');
  let step = $state<Step | null>(null);
  let result = $state<{ value: number; expected: number; jobId: string; ciphertextBytes: number } | null>(null);
  let inputBytes = $state(0);
  let computeError = $state('');
  let destroyed = false;

  // Checked in the browser only: server-side rendering has no Worker.
  let supported = $state(true);
  const unlockedKeyId = $derived(fheSession.unlockedKeyId);
  const localEntries = $derived(
    (overview?.entries ?? []).filter((e): e is LocalEntry => e.local !== undefined)
  );
  const chosen = $derived(localEntries.find((e) => e.server.id === chosenKeyId) ?? localEntries[0]);
  const opInfo = $derived(OPERATIONS.find((o) => o.id === operation) ?? OPERATIONS[0]);
  const valid = $derived(isUint16(val1) && isUint16(val2));
  const expected = $derived(valid ? expectedResult(operation, val1, val2) : null);

  onMount(async () => {
    supported = fheSession.supported;
    if (!supported) return;
    try {
      overview = await loadKeyOverview();
    } catch (e) {
      loadError = errorMessage(e, 'Could not load your keys.');
    }
  });

  onDestroy(() => {
    destroyed = true;
  });

  async function waitForJob(jobId: string): Promise<JobSummary> {
    const deadline = Date.now() + JOB_TIMEOUT_MS;
    for (;;) {
      const job = await compute.getJobStatus(jobId);
      if (job.status === 'completed' || job.status === 'failed') return job;
      if (destroyed) throw new Error('Cancelled');
      if (Date.now() > deadline) throw new Error('The computation timed out');
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  }

  async function run(event: SubmitEvent) {
    event.preventDefault();
    if (!unlockedKeyId || !valid || expected === null) return;
    const want = expected;
    computeError = '';
    result = null;
    try {
      step = 'encrypting';
      const [a, b] = await fheSession.encrypt([val1, val2]);
      inputBytes = a.length + b.length;

      step = 'submitting';
      const job = await compute.submitJob(unlockedKeyId, operation, [bytesToBase64(a), bytesToBase64(b)]);

      step = 'computing';
      const done = await waitForJob(job.id);
      if (done.status === 'failed') {
        throw new Error(done.error_message ?? 'The computation failed');
      }
      const ciphertext = await compute.getJobResult(job.id);

      step = 'decrypting';
      const value = await fheSession.decrypt(ciphertext);
      result = { value, expected: want, jobId: job.id, ciphertextBytes: ciphertext.length };
    } catch (e) {
      computeError = errorMessage(e, 'Computation failed');
    } finally {
      step = null;
    }
  }

  function chooseOperation(op: Operation) {
    operation = op;
    result = null;
    computeError = '';
  }

  function randomizeValues() {
    val1 = Math.floor(Math.random() * (UINT16_MAX + 1));
    val2 = Math.floor(Math.random() * (UINT16_MAX + 1));
  }

  function formatBytes(n: number): string {
    return n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)} MB` : `${(n / 1000).toFixed(1)} KB`;
  }

  const STEP_LABELS: Record<Step, string> = {
    encrypting: 'Encrypting in your browser…',
    submitting: 'Sending ciphertexts…',
    computing: 'Server computing on encrypted data…',
    decrypting: 'Decrypting in your browser…'
  };
</script>

<svelte:head><title>Dashboard · HEaaS</title></svelte:head>

<div class="dashboard">
  <div class="page-header">
    <div class="page-title-row">
      <div class="live-dot" aria-hidden="true"></div>
      <h1>Homomorphic Compute Dashboard</h1>
    </div>
    <div class="spec-row">
      <span class="spec">TFHE (CGGI) · TFHE-rs</span>
      <span class="spec-sep" aria-hidden="true">•</span>
      <span class="spec">FheUint16</span>
      <span class="spec-sep" aria-hidden="true">•</span>
      <span class="spec">Keys stay in your browser</span>
    </div>
  </div>

  <section class="card key-card" aria-labelledby="key-title" aria-live="polite">
    <h2 id="key-title" class="card-title">Your encryption key</h2>

    {#if !supported}
      <p class="error-text">
        In-browser encryption needs a cross-origin isolated page (and Web Workers), which this
        browser or deployment does not provide.
      </p>
    {:else if loadError}
      <p class="error-text" role="alert">{loadError}</p>
    {:else if unlockedKeyId}
      <div class="key-row">
        <span class="badge badge-green">Ready</span>
        <code class="key-id" title={unlockedKeyId}>{unlockedKeyId}</code>
        <button type="button" class="btn-ghost btn-sm" onclick={() => fheSession.lock()}>Lock</button>
      </div>
      <p class="field-hint">Unlocked until you lock it, reload the page or sign out.</p>
    {:else if !overview}
      <p class="key-status"><span class="spinner" aria-hidden="true"></span> Loading keys…</p>
    {:else if chosen}
      {#if localEntries.length > 1}
        <label for="key-choice">Key</label>
        <select id="key-choice" bind:value={chosenKeyId}>
          {#each localEntries as entry (entry.server.id)}
            <option value={entry.server.id}>{entry.server.id}</option>
          {/each}
        </select>
      {/if}
      <p class="field-hint">Enter your passphrase to use your key in this tab.</p>
      {#key chosen.server.id}
        <UnlockForm entry={chosen} />
      {/key}
    {:else}
      <p class="field-hint">
        {overview.entries.length > 0
          ? 'Your keys were created in another browser. Import a backup to use one here.'
          : 'You have no encryption key yet.'}
      </p>
      <a class="btn-primary link-button" href={resolve('/keys')}>
        {overview.entries.length > 0 ? 'Import a key' : 'Create a key'}
      </a>
    {/if}
  </section>

  {#if unlockedKeyId}
    <section class="card compute-card" aria-labelledby="compute-title">
      <div class="card-header">
        <h2 id="compute-title" class="card-title">New Computation</h2>
        <button type="button" class="btn-secondary btn-sm randomize" onclick={randomizeValues}>Randomize values</button>
        <p class="card-subtitle">Encrypted locally, computed on ciphertext, decrypted locally.</p>
      </div>

      <form onsubmit={run} class="compute-form">
        <div class="field-block">
          <div id="op-label" class="label-like">Operation</div>
          <div class="op-tabs" role="group" aria-labelledby="op-label">
            {#each OPERATIONS as op (op.id)}
              <button
                type="button"
                class="op-tab"
                class:active={operation === op.id}
                aria-pressed={operation === op.id}
                onclick={() => chooseOperation(op.id)}
              >
                {op.label}
              </button>
            {/each}
          </div>
          <p class="field-hint">Unsigned 16-bit integers (0–65535); arithmetic wraps around modulo 65536.</p>
        </div>

        <div class="inputs-row">
          <div class="field-block">
            <label for="val1">Value A <span class="required" aria-hidden="true">*</span></label>
            <input id="val1" type="number" bind:value={val1} min="0" max={UINT16_MAX} step="1" required />
          </div>
          <div class="op-glyph" aria-hidden="true">{opInfo.symbol}</div>
          <div class="field-block">
            <label for="val2">Value B <span class="required" aria-hidden="true">*</span></label>
            <input id="val2" type="number" bind:value={val2} min="0" max={UINT16_MAX} step="1" required />
          </div>
          <div class="op-glyph" aria-hidden="true">=</div>
          <div class="field-block expected-block">
            <div class="label-like">Expected</div>
            <div class="expected-val">{expected ?? '—'}</div>
          </div>
        </div>

        <button type="submit" class="btn-primary" disabled={step !== null || !valid}>
          {#if step}
            <span class="spinner" aria-hidden="true"></span> {STEP_LABELS[step]}
          {:else}
            Run
          {/if}
        </button>
      </form>
    </section>
  {/if}

  {#if computeError}
    <div class="card result-card error-card" role="alert">
      <div class="result-header">
        <span class="badge badge-red">Error</span>
        <button class="btn-ghost dismiss-btn" onclick={() => (computeError = '')} type="button">Dismiss</button>
      </div>
      <p class="error-text">{computeError}</p>
    </div>
  {/if}

  {#if result}
    <div class="card result-card success-card" aria-live="polite">
      <div class="result-header">
        <div class="badge-group">
          <span class="badge badge-green">Decrypted locally</span>
          {#if result.value === result.expected}
            <span class="badge badge-green badge-match">Matches expected</span>
          {:else}
            <span class="badge badge-red">Does not match {result.expected}</span>
          {/if}
        </div>
        <button class="btn-ghost dismiss-btn" onclick={() => (result = null)} type="button">Clear</button>
      </div>

      <div class="result-plaintext">
        <div class="result-label-row">
          <span class="result-label">Result</span>
        </div>
        <span class="result-number" data-testid="result-value">{result.value}</span>
      </div>

      <div class="divider"></div>

      <dl class="result-facts">
        <div><dt>Sent to the server</dt><dd>2 ciphertexts, {formatBytes(inputBytes)}</dd></div>
        <div><dt>Received</dt><dd>1 ciphertext, {formatBytes(result.ciphertextBytes)}</dd></div>
        <div><dt>Job</dt><dd><code>{result.jobId}</code> · <a href={resolve('/jobs')}>all jobs</a></dd></div>
      </dl>
    </div>
  {/if}
</div>

<style>
  .dashboard { display: flex; flex-direction: column; gap: 1rem; }

  /* ── Page header ─────────────────────────────────── */
  .page-header { margin-bottom: 0.25rem; }

  .page-title-row {
    display: flex; align-items: center; gap: 0.625rem;
    margin-bottom: 0.5rem;
  }

  .live-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--success);
    box-shadow: 0 0 6px var(--success);
    flex-shrink: 0;
  }

  .spec-row {
    display: flex; align-items: center; flex-wrap: wrap; gap: 0.25rem;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-muted);
  }
  .spec { color: var(--text-secondary); }
  .spec-sep { color: var(--text-muted); }

  /* ── Compute card ────────────────────────────────── */
  .compute-card {
    background-image: radial-gradient(circle, rgba(255,255,255,0.025) 1px, transparent 1px);
    background-size: 22px 22px;
  }

  .card-header {
    display: flex; align-items: baseline; flex-wrap: wrap; gap: 0.5rem;
    margin-bottom: 1.5rem;
  }
  .card-title { font-weight: 600; font-size: 0.9375rem; letter-spacing: normal; }
  .card-subtitle {
    font-size: 0.775rem; color: var(--text-secondary); flex-basis: 100%;
    line-height: 1.4;
  }
  .randomize { margin-left: auto; }
  .key-card .card-title { margin-bottom: 0.75rem; }
  .link-button { display: inline-block; text-decoration: none; }
  .result-facts a { color: #a5b4fc; }

  .compute-form { display: flex; flex-direction: column; gap: 0; }

  /* ── Op tabs ─────────────────────────────────────── */
  .field-block { display: flex; flex-direction: column; }
  .label-like {
    display: block;
    margin-bottom: 0.375rem;
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-secondary);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .op-tabs {
    display: inline-flex; gap: 0.25rem;
    background: var(--bg-secondary);
    padding: 0.2rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-strong);
    margin-bottom: 1rem;
  }
  .op-tab {
    display: flex; align-items: center; gap: 0.35rem;
    padding: 0.375rem 0.875rem;
    border-radius: 4px;
    font-size: 0.8375rem; font-weight: 500;
    color: var(--text-secondary);
    background: transparent; border: none;
    transition: background 0.15s, color 0.15s;
  }
  .op-tab:hover { color: var(--text-primary); }
  .op-tab.active {
    background: var(--surface-elevated);
    color: var(--text-primary);
    box-shadow: 0 1px 3px rgba(0,0,0,0.35);
  }

  .field-hint { font-size: 0.7375rem; color: var(--text-muted); margin-top: -0.625rem; margin-bottom: 1rem; }

  /* ── Inputs row ──────────────────────────────────── */
  .inputs-row {
    display: grid;
    grid-template-columns: 1fr auto 1fr auto 0.75fr;
    align-items: end;
    gap: 0.625rem;
    margin-bottom: 1.25rem;
  }
  .field-block label { margin-bottom: 0.3rem; }
  .field-block input { margin-bottom: 0; }

  .op-glyph {
    font-family: var(--font-mono);
    font-size: 1.125rem; font-weight: 400;
    color: var(--text-muted);
    padding-bottom: 0.625rem;
    user-select: none;
  }

  .expected-block { opacity: 0.8; }
  .expected-val {
    padding: 0.575rem 0.75rem;
    background: var(--bg-secondary);
    border: 1px dashed rgba(255,255,255,0.08);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: 0.9375rem;
    color: var(--text-secondary);
  }

  /* ── Result card ─────────────────────────────────── */
  .result-card { margin-top: 0; }
  .result-header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 1rem;
  }
  .badge-group { display: flex; gap: 0.5rem; }
  .dismiss-btn { font-size: 0.775rem; padding: 0.2rem 0.5rem; }

  .success-card { border-color: rgba(16,185,129,0.18); }
  .error-card   { border-color: rgba(239,68,68,0.18); }
  .error-text { color: var(--error); font-size: 0.9375rem; }

  .result-plaintext { margin-bottom: 0; }
  .result-label-row { margin-bottom: 0.25rem; }
  .result-label {
    font-size: 0.6875rem; font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.08em; text-transform: uppercase;
  }
  .badge-match { margin-left: 0.5rem; vertical-align: middle; }
  .result-number {
    font-family: var(--font-mono);
    font-size: 3rem; font-weight: 700;
    color: var(--success);
    letter-spacing: -0.03em;
    line-height: 1;
  }

  @media (max-width: 600px) {
    .inputs-row {
      grid-template-columns: 1fr 1fr;
    }
    .op-glyph { display: none; }
    .expected-block { grid-column: span 2; }
  }
  /* ── Key card ───────────────────────────────────── */
  .key-status { display: flex; align-items: center; gap: 0.5rem; color: var(--text-secondary); }
  .key-row { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  .key-id {
    font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 22ch;
  }

  .result-facts { display: grid; gap: 0.35rem; margin: 0; font-size: 0.85rem; }
  .result-facts div { display: flex; gap: 0.75rem; }
  .result-facts dt { color: var(--text-muted); min-width: 10rem; }
  .result-facts dd { margin: 0; color: var(--text-secondary); font-family: var(--font-mono); overflow-wrap: anywhere; }
</style>
