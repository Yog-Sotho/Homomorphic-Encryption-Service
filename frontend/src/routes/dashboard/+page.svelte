<script lang="ts">
  import { onMount } from 'svelte';
  import { compute } from '$lib/api';
  import { userStore } from '$lib/stores';

  let val1 = 0;
  let val2 = 0;
  let operation = 'add';
  let jobId = '';
  let result = '';
  let status = '';
  let loading = false;
  let copied = false;

  async function copyResult() {
    try {
      await navigator.clipboard.writeText(result);
      copied = true;
      setTimeout(() => copied = false, 2000);
    } catch (err) {
      console.error('Failed to copy: ', err);
    }
  }

  async function submitJob() {
    loading = true;
    status = '';
    result = '';
    
    const payload = JSON.stringify([val1.toString(), val2.toString()]);
    const b64 = btoa(payload);

    try {
      const res = await compute.submitJob(b64, operation);
      jobId = res.data.id;
      pollStatus(jobId);
    } catch (e: any) {
      status = 'Error submitting job';
    } finally {
      loading = false;
    }
  }

  async function pollStatus(id: string) {
    const interval = setInterval(async () => {
      try {
        const res = await compute.getJobStatus(id);
        status = res.data.status;
        if (res.data.status === 'completed') {
          clearInterval(interval);
          result = res.data.result_b64 || 'No result';
        } else if (res.data.status === 'failed') {
          clearInterval(interval);
          status = `Failed: ${res.data.error_message}`;
        }
      } catch (e) {
        clearInterval(interval);
      }
    }, 1000);
  }
</script>

<div class="dashboard">
  <h1>Homomorphic Compute Dashboard</h1>
  <div class="card">
    <h2>New Computation</h2>
    <form on:submit|preventDefault={submitJob}>
      <label for="val1">Value 1</label>
      <input id="val1" type="number" bind:value={val1} placeholder="Value 1" required />

      <label for="val2">Value 2</label>
      <input id="val2" type="number" bind:value={val2} placeholder="Value 2" required />

      <label for="operation">Operation</label>
      <select id="operation" bind:value={operation}>
        <option value="add">Add</option>
        <option value="multiply">Multiply</option>
      </select>

      <button type="submit" class="btn-primary" disabled={loading}>
        {loading ? 'Processing...' : 'Compute'}
      </button>
    </form>
  </div>

  {#if jobId}
    <div class="card" aria-live="polite">
      <h2>Job Status</h2>
      <p>ID: {jobId}</p>
      <p>Status: {status}</p>
      {#if result}
        <div class="result-container">
          <p>Result (Base64):</p>
          <code class="result-block">{result}</code>
          <div class="result-actions">
            <button type="button" class="btn-secondary btn-sm" on:click={copyResult}>
              {copied ? 'Copied!' : 'Copy to Clipboard'}
            </button>
            {#if copied}
              <span class="success" role="status">Text copied!</span>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .dashboard { padding: 2rem; }
  .result-container { margin-top: 1rem; }
  .result-block {
    display: block;
    background: var(--bg-primary);
    padding: 1rem;
    border-radius: var(--radius);
    border: 1px solid var(--border);
    margin: 0.5rem 0;
    word-break: break-all;
    font-family: monospace;
    max-height: 200px;
    overflow-y: auto;
  }
  .result-actions { display: flex; align-items: center; gap: 1rem; margin-top: 0.5rem; }
  :global(.btn-sm) { padding: 0.4rem 0.8rem; font-size: 0.875rem; width: auto; }
</style>