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

  async function runSandbox() {
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

<div class="page">
  <!-- Page header -->
  <div class="page-header">
    <div>
      <h1>Homomorphic Compute</h1>
      <p class="text-muted" style="margin-top:0.4rem">
        Arithmetic on encrypted data — the server never sees your plaintext values.
      </p>
    </div>
    <span class="badge badge-green">Live</span>
  </div>

  <!-- Info banner -->
  <div class="info-banner">
    <div class="info-icon">🔐</div>
    <div>
      <strong>Sandbox mode — server-managed keys</strong>
      <p>
        Inputs are encrypted server-side using BFV (TFHE-rs), the homomorphic operation
        is performed on the ciphertexts, and the plaintext is recovered only at the final
        decryption step. Arithmetic is modular — results wrap around 65 536.
      </p>
    </div>
  </div>

  <!-- Compute form -->
  <div class="card compute-card">
    <h2>New Computation</h2>

    <form on:submit|preventDefault={runSandbox} style="margin-top:1.25rem">
      <!-- Operation selector -->
      <div class="field-group">
        <label for="operation">Operation</label>
        <div class="op-tabs" id="operation">
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
          <p class="field-hint">Values capped at 255 to prevent modular wrap-around.</p>
        {/if}
      </div>

      <!-- Value inputs -->
      <div class="inputs-row">
        <div class="field-group">
          <label for="val1">Value A</label>
          <input
            id="val1"
            type="number"
            bind:value={val1}
            min="0"
            max={maxVal}
            required
          />
        </div>
        <div class="op-divider" aria-hidden="true">
          {operation === 'add' ? '+' : '×'}
        </div>
        <div class="field-group">
          <label for="val2">Value B</label>
          <input
            id="val2"
            type="number"
            bind:value={val2}
            min="0"
            max={maxVal}
            required
          />
        </div>
        <div class="op-divider" aria-hidden="true">=</div>
        <div class="field-group expected">
          <label>Expected</label>
          <div class="expected-val">{expectedResult}</div>
        </div>
      </div>

      <button type="submit" class="btn-primary" disabled={loading}>
        {#if loading}
          <span class="spinner"></span> Computing…
        {:else}
          Run Computation
        {/if}
      </button>
    </form>
  </div>

  <!-- Error state -->
  {#if errorMessage}
    <div class="card result-card error-card">
      <div class="result-header">
        <span class="badge badge-red">Error</span>
        <button class="btn-ghost" on:click={clearResults} type="button">Dismiss</button>
      </div>
      <p class="error-text">{errorMessage}</p>
    </div>
  {/if}

  <!-- Result state -->
  {#if plaintextResult !== null}
    <div class="card result-card success-card">
      <div class="result-header">
        <span class="badge badge-green">Result</span>
        <button class="btn-ghost" on:click={clearResults} type="button">Clear</button>
      </div>

      <div class="result-plaintext">
        <span class="result-label">Plaintext</span>
        <span class="result-number">{plaintextResult}</span>
      </div>

      <div class="divider"></div>

      <div class="ciphertext-section">
        <div class="ciphertext-header">
          <span class="result-label">Ciphertext (Base64)</span>
          <div class="ciphertext-actions">
            <button class="btn-secondary" type="button" on:click={() => showFullCiphertext = !showFullCiphertext}>
              {showFullCiphertext ? 'Collapse' : 'Expand'}
            </button>
            <button class="btn-secondary" type="button" on:click={() => copyToClipboard(resultB64)}>
              {copied ? '✓ Copied' : 'Copy'}
            </button>
          </div>
        </div>
        <code class="ciphertext-value" class:collapsed={!showFullCiphertext}>
          {resultB64}
        </code>
        {#if !showFullCiphertext}
          <p class="ciphertext-note">
            {resultB64.length} chars — this is the actual encrypted ciphertext produced by TFHE-rs.
          </p>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .page { display: flex; flex-direction: column; gap: 1rem; }

  .page-header {
    display: flex; align-items: flex-start; justify-content: space-between;
    margin-bottom: 0.5rem;
  }

  .info-banner {
    display: flex; gap: 1rem; align-items: flex-start;
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: var(--radius);
    padding: 1rem 1.25rem;
    font-size: 0.875rem;
  }
  .info-icon { font-size: 1.25rem; flex-shrink: 0; margin-top: 0.1rem; }
  .info-banner strong { display: block; margin-bottom: 0.25rem; color: var(--text-primary); font-size: 0.875rem; }
  .info-banner p { color: var(--text-secondary); line-height: 1.5; }

  .compute-card h2 { margin-bottom: 0; }

  /* Op tabs */
  .op-tabs {
    display: inline-flex; gap: 0.375rem;
    background: var(--bg-secondary);
    padding: 0.25rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-strong);
    margin-bottom: 1.125rem;
  }
  .op-tab {
    display: flex; align-items: center; gap: 0.375rem;
    padding: 0.4rem 1rem;
    border-radius: 4px;
    font-size: 0.875rem; font-weight: 500;
    color: var(--text-secondary);
    background: transparent; border: none;
    transition: background 0.15s, color 0.15s;
  }
  .op-tab:hover { color: var(--text-primary); }
  .op-tab.active { background: var(--surface-elevated); color: var(--text-primary); box-shadow: 0 1px 4px rgba(0,0,0,0.3); }
  .op-sym { font-family: var(--font-mono); font-size: 1rem; color: var(--accent); }

  .field-hint { font-size: 0.75rem; color: var(--text-secondary); margin-top: -0.75rem; margin-bottom: 1rem; }

  /* Inputs row */
  .inputs-row {
    display: grid;
    grid-template-columns: 1fr auto 1fr auto 0.8fr;
    align-items: end;
    gap: 0.75rem;
    margin-bottom: 1.25rem;
  }
  .field-group { display: flex; flex-direction: column; }
  .field-group label { margin-bottom: 0.375rem; }
  .field-group input { margin-bottom: 0; }

  .op-divider {
    font-family: var(--font-mono);
    font-size: 1.25rem; font-weight: 500;
    color: var(--text-secondary);
    padding-bottom: 0.65rem;
    user-select: none;
  }

  .expected { opacity: 0.75; }
  .expected-val {
    padding: 0.6rem 0.875rem;
    background: var(--bg-secondary);
    border: 1px dashed var(--border-strong);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: 0.9375rem;
    color: var(--text-secondary);
  }

  /* Results */
  .result-card { margin-top: 0; }
  .result-header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 1.125rem;
  }

  .success-card { border-color: rgba(16,185,129,0.2); }
  .error-card   { border-color: rgba(239,68,68,0.2); }
  .error-text { color: var(--error); font-size: 0.9375rem; }

  .result-plaintext {
    display: flex; align-items: baseline; gap: 1rem;
    margin-bottom: 0;
  }
  .result-label {
    font-size: 0.75rem; font-weight: 600;
    color: var(--text-secondary);
    letter-spacing: 0.06em; text-transform: uppercase;
    flex-shrink: 0;
  }
  .result-number {
    font-family: var(--font-mono);
    font-size: 2.25rem; font-weight: 700;
    color: var(--success);
    letter-spacing: -0.02em;
    line-height: 1;
  }

  .ciphertext-section { display: flex; flex-direction: column; gap: 0.625rem; }
  .ciphertext-header {
    display: flex; justify-content: space-between; align-items: center;
  }
  .ciphertext-actions { display: flex; gap: 0.375rem; }
  .ciphertext-value {
    font-family: var(--font-mono);
    font-size: 0.75rem;
    color: var(--text-secondary);
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.75rem;
    word-break: break-all;
    line-height: 1.6;
    transition: max-height 0.2s;
  }
  .ciphertext-value.collapsed {
    max-height: 3.6rem;
    overflow: hidden;
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
  }
  .ciphertext-note {
    font-size: 0.75rem;
    color: var(--text-muted);
  }

  @media (max-width: 600px) {
    .inputs-row {
      grid-template-columns: 1fr 1fr;
      grid-template-rows: auto auto auto;
    }
    .op-divider { display: none; }
    .expected { grid-column: span 2; }
  }
</style>
