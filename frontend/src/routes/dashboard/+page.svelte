<script lang="ts">
  import { onDestroy } from 'svelte';
  import { compute } from '$lib/api';
  import { userStore } from '$lib/stores';

  let val1 = 0;
  let val2 = 0;
  let operation = 'add';
  let loading = false;
  let copied = false;

  // Result state
  let plaintextResult: number | null = null;
  let resultB64 = '';
  let errorMessage = '';

  // onDestroy is provided for future extension (e.g. WebSocket or polling).
  // B3 — no interval is started in sandbox mode so no cleanup is needed,
  // but the hook is wired correctly so any future interval reference can be
  // cleared here without a memory leak.
  let _intervalHandle: ReturnType<typeof setInterval> | null = null;
  onDestroy(() => {
    if (_intervalHandle !== null) {
      clearInterval(_intervalHandle);
    }
  });

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch (err) {
      console.error('Failed to copy: ', err);
    }
  }

  function clearResults() {
    plaintextResult = null;
    resultB64 = '';
    errorMessage = '';
  }

  // C9 — calls the synchronous sandbox endpoint: no polling required.
  async function runSandbox() {
    loading = true;
    clearResults();

    try {
      const res = await compute.sandboxCompute(val1, val2, operation);
      plaintextResult = res.data.plaintext_result;
      resultB64 = res.data.result_b64;
    } catch (e: any) {
      errorMessage =
        e?.response?.data?.message ?? e?.message ?? 'Unknown error';
    } finally {
      loading = false;
    }
  }
</script>

<div class="dashboard">
  <h1>Homomorphic Compute Dashboard</h1>

  <!-- Sandbox notice -->
  <div class="notice">
    <strong>Sandbox mode:</strong> Values are encrypted server-side, the
    homomorphic operation is performed on the ciphertexts, and the result is
    decrypted — all within a single synchronous request. No job queue is used.
  </div>

  <div class="card">
    <h2>New Computation</h2>
    <form on:submit|preventDefault={runSandbox}>
      <label for="val1">Value 1 (0–1023)</label>
      <input
        id="val1"
        type="number"
        bind:value={val1}
        min="0"
        max="1023"
        placeholder="Value 1"
        required
      />

      <label for="val2">Value 2 (0–1023)</label>
      <input
        id="val2"
        type="number"
        bind:value={val2}
        min="0"
        max="1023"
        placeholder="Value 2"
        required
      />

      <label for="operation">Operation</label>
      <select id="operation" bind:value={operation}>
        <option value="add">Add</option>
        <option value="multiply">Multiply</option>
      </select>

      <button type="submit" class="btn-primary" disabled={loading}>
        {loading ? 'Processing…' : 'Compute'}
      </button>
    </form>
  </div>

  {#if errorMessage}
    <div class="card error-card">
      <p class="error-text">Error: {errorMessage}</p>
      <button class="btn-secondary btn-sm" on:click={clearResults} type="button">Dismiss</button>
    </div>
  {/if}

  {#if plaintextResult !== null}
    <div class="card">
      <div class="card-header">
        <h2>Result</h2>
        <button class="btn-secondary btn-sm" on:click={clearResults} type="button">Clear</button>
      </div>

      <p>
        Plaintext result: <strong class="result-plain">{plaintextResult}</strong>
      </p>

      <div class="result-container">
        <p>Ciphertext (Base64):</p>
        <code class="result-text">{resultB64}</code>
        <button
          class="btn-secondary btn-sm"
          on:click={() => copyToClipboard(resultB64)}
          aria-label="Copy ciphertext result to clipboard"
          type="button"
        >
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>
    </div>
  {/if}
</div>

<style>
  .dashboard { padding: 2rem; }
  .notice {
    background: var(--bg-secondary, #1e293b);
    border-left: 4px solid var(--accent, #6366f1);
    padding: 0.75rem 1rem;
    border-radius: 4px;
    margin-bottom: 1.5rem;
    font-size: 0.9rem;
  }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
  .card-header h2 { margin-bottom: 0; }
  .result-plain { font-size: 1.4rem; }
  .result-container { margin-top: 1rem; display: flex; align-items: flex-start; gap: 0.5rem; flex-wrap: wrap; }
  .result-text {
    background: var(--bg-primary, #0f172a);
    padding: 0.2rem 0.4rem;
    border-radius: 4px;
    word-break: break-all;
    flex: 1 1 100%;
  }
  .error-card { border-left: 4px solid #ef4444; }
  .error-text { color: #ef4444; margin: 0 0 0.75rem; }
</style>
