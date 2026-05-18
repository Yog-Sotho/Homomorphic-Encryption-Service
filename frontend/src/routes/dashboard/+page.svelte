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
    <div class="card">
      <h2>Job Status</h2>
      <p>ID: {jobId}</p>
      <p>Status: {status}</p>
      {#if result}
        <p>Result (Base64): {result}</p>
      {/if}
    </div>
  {/if}
</div>

<style>
  .dashboard { padding: 2rem; }
</style>