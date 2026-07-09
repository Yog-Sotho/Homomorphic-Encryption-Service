<script lang="ts">
  import { onDestroy } from 'svelte';
  import { compute } from '$lib/api';

  let val1 = 10;
  let val2 = 5;
  let operation = 'add';
  let loading = false;

  let plaintextResult: number | null = null;
  let resultB64 = '';
  let errorMessage = '';
  let showFullCiphertext = false;
  let copied = false;

  let _intervalHandle: ReturnType<typeof setInterval> | null = null;
  onDestroy(() => { if (_intervalHandle !== null) clearInterval(_intervalHandle); });

  $: maxVal = operation === 'multiply' ? 255 : 65535;
  $: val1Clamped = Math.min(val1, maxVal);
  $: val2Clamped = Math.min(val2, maxVal);
  $: expectedResult = operation === 'add'
    ? (val1Clamped + val2Clamped) % 65536
    : (val1Clamped * val2Clamped) % 65536;

  function clearResults() {
    plaintextResult = null;
    resultB64 = '';
    errorMessage = '';
    showFullCiphertext = false;
  }

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => copied = false, 2000);
    } catch {}
  }

  function clearDashboard() {
    jobId = '';
    status = '';
    result = '';
  }

  function randomizeValues() {
    val1 = Math.floor(Math.random() * 1024);
    val2 = Math.floor(Math.random() * 1024);
  }

  async function submitJob() {
    loading = true;
    clearResults();
    try {
      const res = await compute.sandboxCompute(val1Clamped, val2Clamped, operation);
      plaintextResult = res.data.plaintext_result;
      resultB64 = res.data.result_b64;
    } catch (e: any) {
      errorMessage = e?.response?.data?.message ?? e?.message ?? 'Computation failed';
    } finally {
      loading = false;
    }
  }
</script>

<div class="dashboard">
  <h1>Homomorphic Compute Dashboard</h1>
  <div class="card">
    <div class="card-header">
      <h2>New Computation</h2>
      <button type="button" class="btn-secondary btn-sm" on:click={randomizeValues}>Randomize</button>
    </div>
    <form on:submit|preventDefault={submitJob}>
      <label for="val1">Value 1 (0-1023)</label>
      <input id="val1" type="number" bind:value={val1} min="0" max="1023" placeholder="Value 1" required />

    <form on:submit|preventDefault={runSandbox} class="compute-form">
      <div class="field-block">
        <label id="op-label">Operation</label>
        <div class="op-tabs" role="group" aria-labelledby="op-label">
          <button
            type="button"
            class="op-tab"
            class:active={operation === 'add'}
            on:click={() => { operation = 'add'; clearResults(); }}
          >
            <span class="op-sym">+</span> Add
          </button>
          <button
            type="button"
            class="op-tab"
            class:active={operation === 'multiply'}
            on:click={() => { operation = 'multiply'; clearResults(); }}
          >
            <span class="op-sym">×</span> Multiply
          </button>
        </div>
        {#if operation === 'multiply'}
          <p class="field-hint">Values capped at 255 — multiplying larger integers wraps around mod 65536.</p>
        {/if}
      </div>

      <div class="inputs-row">
        <div class="field-block">
          <label for="val1">Value A</label>
          <input id="val1" type="number" bind:value={val1} min="0" max={maxVal} required />
        </div>
        <div class="op-glyph" aria-hidden="true">{operation === 'add' ? '+' : '×'}</div>
        <div class="field-block">
          <label for="val2">Value B</label>
          <input id="val2" type="number" bind:value={val2} min="0" max={maxVal} required />
        </div>
        <div class="op-glyph" aria-hidden="true">=</div>
        <div class="field-block expected-block">
          <label>Expected</label>
          <div class="expected-val">{expectedResult}</div>
        </div>
      </div>

      <button type="submit" class="btn-primary" disabled={loading}>
        {#if loading}
          <span class="spinner"></span> Computing…
        {:else}
          Run
        {/if}
      </button>
    </form>
  </div>

  {#if errorMessage}
    <div class="card result-card error-card">
      <div class="result-header">
        <span class="badge badge-red">Error</span>
        <button class="btn-ghost dismiss-btn" on:click={clearResults} type="button">Dismiss</button>
      </div>
      <p class="error-text">{errorMessage}</p>
    </div>
  {/if}

  {#if plaintextResult !== null}
    <div class="card result-card success-card">
      <div class="result-header">
        <span class="badge badge-green">Result</span>
        <button class="btn-ghost dismiss-btn" on:click={clearResults} type="button">Clear</button>
      </div>

      <div class="result-plaintext">
        <div class="result-label-row">
          <span class="result-label">Plaintext</span>
        </div>
        <span class="result-number">{plaintextResult}</span>
      </div>

      <div class="divider"></div>

      <div class="ciphertext-section">
        <div class="ciphertext-header">
          <span class="result-label">Ciphertext</span>
          <span class="ct-meta">{resultB64.length} chars · TFHE-rs BFV</span>
          <div class="ciphertext-actions">
            <button class="btn-secondary" type="button" on:click={() => showFullCiphertext = !showFullCiphertext}>
              {showFullCiphertext ? 'Collapse' : 'Expand'}
            </button>
            <button class="btn-secondary" type="button" on:click={() => copyToClipboard(resultB64)}>
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
        </div>
        <code class="ciphertext-value" class:collapsed={!showFullCiphertext}>{resultB64}</code>
      </div>
    </div>
  {/if}
</div>

<style>
  .page { display: flex; flex-direction: column; gap: 1rem; }

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
  .op-sym { font-family: var(--font-mono); font-size: 0.95rem; color: var(--accent); }

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
  .result-number {
    font-family: var(--font-mono);
    font-size: 3rem; font-weight: 700;
    color: var(--success);
    letter-spacing: -0.03em;
    line-height: 1;
  }

  .ciphertext-section { display: flex; flex-direction: column; gap: 0.5rem; }
  .ciphertext-header {
    display: flex; align-items: center; gap: 0.625rem; flex-wrap: wrap;
  }
  .ct-meta {
    font-family: var(--font-mono);
    font-size: 0.7rem; color: var(--text-muted);
    margin-right: auto;
  }
  .ciphertext-actions { display: flex; gap: 0.3rem; }
  .ciphertext-value {
    font-family: var(--font-mono);
    font-size: 0.7rem;
    color: var(--text-muted);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.625rem 0.75rem;
    word-break: break-all;
    line-height: 1.7;
  }
  .ciphertext-value.collapsed {
    max-height: 3.4rem;
    overflow: hidden;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
  }

  @media (max-width: 600px) {
    .inputs-row {
      grid-template-columns: 1fr 1fr;
    }
    .op-glyph { display: none; }
    .expected-block { grid-column: span 2; }
  }
</style>
