<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import {
    compute,
    errorMessage as messageOf,
    keys,
    type JobSummary,
    type Operation,
    type ServerKeyInfo
  } from '#lib/api.js';
  import { FheClient } from '#lib/fhe/client.js';
  import { bytesToBase64 } from '#lib/fhe/encoding.js';
  import { deleteClientKey, getClientKey, saveClientKey } from '#lib/fhe/keystore.js';
  import { OPERATIONS, UINT16_MAX, expectedResult, isUint16 } from '#lib/fhe/operations.js';

  const POLL_INTERVAL_MS = 750;
  const JOB_TIMEOUT_MS = 120_000;

  type KeyState = 'loading' | 'unsupported' | 'none' | 'generating' | 'uploading' | 'ready' | 'error';
  type Step = 'encrypting' | 'submitting' | 'computing' | 'decrypting';

  let fhe: FheClient | null = null;
  let keyState: KeyState = 'loading';
  let activeKey: ServerKeyInfo | null = null;
  /** Server keys this browser has no client key for (e.g. made on another device). */
  let foreignKeys: ServerKeyInfo[] = [];
  let keyError = '';

  let val1 = 10;
  let val2 = 5;
  let operation: Operation = 'add';
  let step: Step | null = null;
  let result: { value: number; expected: number; jobId: string; ciphertextBytes: number } | null = null;
  let inputBytes = 0;
  let computeError = '';
  let destroyed = false;

  $: opInfo = OPERATIONS.find((o) => o.id === operation) ?? OPERATIONS[0];
  $: valid = isUint16(val1) && isUint16(val2);
  $: expected = valid ? expectedResult(operation, val1, val2) : null;
  $: busy = step !== null;

  onMount(async () => {
    if (!FheClient.isSupported()) {
      keyState = 'unsupported';
      return;
    }
    fhe = new FheClient();
    try {
      const serverKeys = await keys.list();
      for (const key of serverKeys) {
        const local = await getClientKey(key.id);
        if (local) {
          await fhe.loadClientKey(local.clientKey);
          activeKey = key;
          break;
        }
      }
      foreignKeys = serverKeys.filter((k) => k.id !== activeKey?.id);
      keyState = activeKey ? 'ready' : 'none';
    } catch (e) {
      keyError = messageOf(e, 'Could not load your keys');
      keyState = 'error';
    }
  });

  onDestroy(() => {
    destroyed = true;
    fhe?.terminate();
  });

  async function generateKey() {
    if (!fhe) return;
    keyError = '';
    try {
      keyState = 'generating';
      const generated = await fhe.generateKeys();
      keyState = 'uploading';
      const info = await keys.upload(new Uint8Array(generated.compressedServerKey));
      try {
        await saveClientKey(info.id, generated.clientKey);
      } catch (e) {
        // Without the client key the server key is useless; don't leave it behind.
        await keys.remove(info.id).catch(() => {});
        throw e;
      }
      activeKey = info;
      keyState = 'ready';
    } catch (e) {
      keyError = messageOf(e, 'Key generation failed');
      keyState = activeKey ? 'ready' : 'none';
    }
  }

  async function forgetKey(key: ServerKeyInfo) {
    keyError = '';
    try {
      await keys.remove(key.id);
      await deleteClientKey(key.id);
      foreignKeys = foreignKeys.filter((k) => k.id !== key.id);
      if (activeKey?.id === key.id) {
        activeKey = null;
        result = null;
        keyState = 'none';
      }
    } catch (e) {
      keyError = messageOf(e, 'Could not delete the key');
    }
  }

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

  async function run() {
    if (!fhe || !activeKey || !valid || expected === null) return;
    const want = expected;
    computeError = '';
    result = null;
    try {
      step = 'encrypting';
      const [a, b] = await fhe.encrypt([val1, val2]);
      inputBytes = a.length + b.length;

      step = 'submitting';
      const job = await compute.submitJob(activeKey.id, operation, [bytesToBase64(a), bytesToBase64(b)]);

      step = 'computing';
      const done = await waitForJob(job.id);
      if (done.status === 'failed') {
        throw new Error(done.error_message ?? 'The computation failed');
      }
      const ciphertext = await compute.getJobResult(job.id);

      step = 'decrypting';
      const value = await fhe.decrypt(ciphertext);
      result = { value, expected: want, jobId: job.id, ciphertextBytes: ciphertext.length };
    } catch (e) {
      computeError = messageOf(e, 'Computation failed');
    } finally {
      step = null;
    }
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

<div class="dashboard">
  <div class="page-header">
    <div class="page-title-row">
      <div class="live-dot"></div>
      <h1>Homomorphic Compute Dashboard</h1>
    </div>
    <div class="spec-row">
      <span class="spec">TFHE (CGGI) · TFHE-rs</span>
      <span class="spec-sep">•</span>
      <span class="spec">FheUint16</span>
      <span class="spec-sep">•</span>
      <span class="spec">Client-side keys</span>
    </div>
  </div>

  <div class="card key-card" aria-live="polite">
    <div class="card-header">
      <div class="card-icon">🔑</div>
      <div class="card-title">Your encryption key</div>
    </div>
    <p class="card-subtitle key-explainer">
      Your secret key is generated in this browser and never leaves it. The server only receives an
      evaluation key, which lets it compute on your ciphertexts but not decrypt them.
    </p>

    {#if keyState === 'loading'}
      <p class="key-status"><span class="spinner"></span> Loading keys…</p>
    {:else if keyState === 'unsupported'}
      <p class="error-text">
        In-browser encryption needs a cross-origin isolated page (and Web Workers), which this
        browser or deployment does not provide.
      </p>
    {:else if keyState === 'error'}
      <p class="error-text">{keyError}</p>
    {:else if keyState === 'generating'}
      <p class="key-status"><span class="spinner"></span> Generating your key pair (a few seconds)…</p>
    {:else if keyState === 'uploading'}
      <p class="key-status"><span class="spinner"></span> Uploading the evaluation key (~60 MB)…</p>
    {:else if keyState === 'none'}
      <button type="button" class="btn-primary" on:click={generateKey}>Generate encryption key</button>
    {:else if activeKey}
      <div class="key-row">
        <span class="badge badge-green">Ready</span>
        <code class="key-id" title={activeKey.id}>{activeKey.id}</code>
        <span class="ct-meta">evaluation key {formatBytes(activeKey.size_bytes)}</span>
        <button type="button" class="btn-ghost btn-sm" on:click={() => activeKey && forgetKey(activeKey)}>
          Delete key
        </button>
      </div>
      <p class="field-hint">
        Stored only in this browser. Clearing site data loses it, and results encrypted under it can
        no longer be decrypted.
      </p>
    {/if}

    {#if keyError && keyState !== 'error'}
      <p class="error-text" role="alert">{keyError}</p>
    {/if}

    {#if foreignKeys.length > 0 && keyState !== 'loading'}
      <details class="foreign-keys">
        <summary>{foreignKeys.length} key(s) registered from another browser</summary>
        <p class="field-hint">This browser does not have their secret keys, so it cannot use them.</p>
        <ul>
          {#each foreignKeys as key (key.id)}
            <li>
              <code class="key-id">{key.id}</code>
              <button type="button" class="btn-ghost btn-sm" on:click={() => forgetKey(key)}>Delete</button>
            </li>
          {/each}
        </ul>
      </details>
    {/if}
  </div>

  {#if keyState === 'ready'}
    <div class="card compute-card">
      <div class="card-header">
        <div class="card-icon">⚡</div>
        <div class="card-title">New Computation</div>
        <p class="card-subtitle">Encrypted locally, computed on ciphertext, decrypted locally.</p>
        <button type="button" class="btn-secondary btn-sm" on:click={randomizeValues} style="margin-left: auto;" aria-label="Randomize input values">Randomize</button>
      </div>

      <form on:submit|preventDefault={run} class="compute-form">
        <div class="field-block">
          <div id="op-label" class="label-like">Operation</div>
          <div class="op-tabs" role="group" aria-labelledby="op-label">
            {#each OPERATIONS as op (op.id)}
              <button
                type="button"
                class="op-tab"
                class:active={operation === op.id}
                aria-pressed={operation === op.id}
                on:click={() => { operation = op.id; result = null; computeError = ''; }}
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

        <button type="submit" class="btn-primary" disabled={busy || !valid}>
          {#if step}
            <span class="spinner"></span> {STEP_LABELS[step]}
          {:else}
            Run
          {/if}
        </button>
      </form>
    </div>
  {/if}

  {#if computeError}
    <div class="card result-card error-card" aria-live="polite">
      <div class="result-header">
        <span class="badge badge-red">Error</span>
        <button class="btn-ghost dismiss-btn" on:click={() => (computeError = '')} type="button">Dismiss</button>
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
        <button class="btn-ghost dismiss-btn" on:click={() => (result = null)} type="button">Clear</button>
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
        <div><dt>Job</dt><dd><code>{result.jobId}</code></dd></div>
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
  .card-icon {
    color: var(--accent); align-self: center;
    flex-shrink: 0; margin-top: 1px;
  }
  .card-title { font-weight: 600; font-size: 0.9375rem; }
  .card-subtitle {
    font-size: 0.775rem; color: var(--text-muted); flex-basis: 100%;
    margin-left: 1.375rem; /* align with title, past icon */
    line-height: 1.4;
  }

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
  .ct-meta {
    font-family: var(--font-mono);
    font-size: 0.7rem; color: var(--text-muted);
    margin-right: auto;
  }

  @media (max-width: 600px) {
    .inputs-row {
      grid-template-columns: 1fr 1fr;
    }
    .op-glyph { display: none; }
    .expected-block { grid-column: span 2; }
  }
  /* ── Key card ───────────────────────────────────── */
  .key-explainer { margin: 0.25rem 0 0.75rem; }
  .key-status { display: flex; align-items: center; gap: 0.5rem; color: var(--text-secondary); }
  .key-row { display: flex; align-items: center; flex-wrap: wrap; gap: 0.5rem; }
  .key-id {
    font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 22ch;
  }
  .foreign-keys { margin-top: 0.75rem; font-size: 0.85rem; color: var(--text-secondary); }
  .foreign-keys ul { list-style: none; padding: 0; margin: 0.5rem 0 0; display: grid; gap: 0.35rem; }
  .foreign-keys li { display: flex; align-items: center; gap: 0.5rem; }

  .result-facts { display: grid; gap: 0.35rem; margin: 0; font-size: 0.85rem; }
  .result-facts div { display: flex; gap: 0.75rem; }
  .result-facts dt { color: var(--text-muted); min-width: 10rem; }
  .result-facts dd { margin: 0; color: var(--text-secondary); font-family: var(--font-mono); overflow-wrap: anywhere; }
</style>
