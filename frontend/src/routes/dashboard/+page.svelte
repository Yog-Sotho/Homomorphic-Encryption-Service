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

  async function copyToClipboard(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
      setTimeout(() => copied = false, 2000);
    } catch (err) {
      console.error('Failed to copy: ', err);
    }
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
    status = '';
    result = '';
    
    const payload = JSON.stringify([val1.toString(), val2.toString()]);
    const b64 = btoa(payload);

    try {
      const res = await compute.submitJob(b64, operation);
      jobId = res.data.id;
      status = 'pending';
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
    <div class="card-header">
      <h2>New Computation</h2>
      <button
        class="btn-secondary btn-sm"
        on:click={randomizeValues}
        aria-label="Randomize input values"
        type="button"
      >
        Randomize
      </button>
    </div>
    <form on:submit|preventDefault={submitJob}>
      <label for="val1">Value 1 (0-1023)</label>
      <input id="val1" type="number" bind:value={val1} min="0" max="1023" placeholder="Value 1" required />

      <label for="val2">Value 2 (0-1023)</label>
      <input id="val2" type="number" bind:value={val2} min="0" max="1023" placeholder="Value 2" required />

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
    <div class="card">
      <div class="card-header">
        <h2>Job Status</h2>
        <button class="btn-secondary btn-sm" on:click={clearDashboard} type="button">Clear</button>
      </div>
      <p>ID: {jobId}</p>
      <p>
        Status:
        <output
          aria-live="polite"
          class="status-text"
          class:success={status === 'completed'}
          class:error={status.startsWith('Failed') || status.startsWith('Error')}
        >
          {status}
        </output>
      </p>
      {#if result}
        <div class="result-container">
          <p>Result (Base64): <code class="result-text">{result}</code></p>
          <button
            class="btn-secondary btn-sm"
            on:click={() => copyToClipboard(result)}
            aria-label="Copy result to clipboard"
            type="button"
          >
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .dashboard { padding: 2rem; }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
  .card-header h2 { margin-bottom: 0; }
  .status-text { font-weight: 500; text-transform: capitalize; }
  .result-container { margin-top: 1rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .result-text { background: var(--bg-primary); padding: 0.2rem 0.4rem; border-radius: 4px; word-break: break-all; }
</style>