<script lang="ts">
  import { onMount } from 'svelte';
  import { resolve } from '$app/paths';
  import { compute, errorMessage, type JobSummary } from '#lib/api.js';
  import { fheSession } from '#lib/fhe/session.svelte.js';
  import { OPERATIONS } from '#lib/fhe/operations.js';
  import { formatProgram } from '#lib/fhe/program.js';

  const PAGE_SIZE = 20;

  let jobs = $state<JobSummary[]>([]);
  let nextCursor = $state<string | null>(null);
  let loading = $state(false);
  let error = $state('');
  /** Decrypted results by job id (only ever held in this page). */
  let decrypted = $state<Record<string, string>>({});

  async function load(cursor?: string) {
    loading = true;
    error = '';
    try {
      const page = await compute.listJobs(cursor, PAGE_SIZE);
      jobs = cursor ? [...jobs, ...page.data] : page.data;
      nextCursor = page.next_cursor;
    } catch (e) {
      error = errorMessage(e, 'Could not load your jobs.');
    } finally {
      loading = false;
    }
  }

  onMount(() => load());

  async function decrypt(job: JobSummary) {
    try {
      const types = job.result_types?.length ? job.result_types : [job.result_type];
      const values: string[] = [];
      for (const [output, ty] of types.entries()) {
        values.push(await fheSession.decrypt(ty, await compute.getJobResult(job.id, output)));
      }
      decrypted[job.id] = values.join(', ');
    } catch (e) {
      decrypted[job.id] = errorMessage(e, 'Could not decrypt');
    }
  }

  async function remove(job: JobSummary) {
    try {
      await compute.deleteJob(job.id);
      jobs = jobs.filter((j) => j.id !== job.id);
    } catch (e) {
      error = errorMessage(e, 'Could not delete the job.');
    }
  }

  /** E.g. "Less (i32, scalar 5, proven)", or "(a + b) * 3 (u8, 2 inputs)". */
  function label(job: JobSummary): string {
    const name = job.program
      ? formatProgram(job.program)
      : (OPERATIONS.find((o) => o.id === job.operation)?.label ?? job.operation);
    const details: string[] = [job.integer_type];
    if (job.operation === 'sum' || job.program) details.push(`${job.input_count} inputs`);
    if (job.scalar !== null) details.push(`scalar ${job.scalar}`);
    if (job.proven) details.push('proven');
    return `${name} (${details.join(', ')})`;
  }

  function when(iso: string): string {
    const date = new Date(iso.endsWith('Z') ? iso : `${iso}Z`);
    return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
  }

  function size(bytes: number | null): string {
    return bytes === null ? '—' : `${(bytes / 1000).toFixed(0)} KB`;
  }

  const TONE: Record<JobSummary['status'], string> = {
    pending: 'indigo',
    processing: 'indigo',
    completed: 'green',
    failed: 'red'
  };
</script>

<svelte:head><title>Jobs · HE Engine</title></svelte:head>

<div class="page">
  <div class="title-row">
    <h1>Jobs</h1>
    <button type="button" class="btn-secondary btn-sm" onclick={() => load()} disabled={loading}>Refresh</button>
  </div>
  <p class="lede">
    Every computation you submitted, newest first. The server stores only ciphertexts; results are
    decrypted here, with the key they were computed under. Finished jobs are deleted after a few
    days.
  </p>
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  {#if jobs.length === 0 && !loading && !error}
    <p class="hint">No jobs yet. Run one from the <a href={resolve('/dashboard')}>dashboard</a>.</p>
  {:else}
    <div class="table-wrap">
      <table>
        <caption class="visually-hidden">Your jobs</caption>
        <thead>
          <tr>
            <th scope="col">Submitted</th>
            <th scope="col">Operation</th>
            <th scope="col">Status</th>
            <th scope="col">Result</th>
            <th scope="col"><span class="visually-hidden">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each jobs as job (job.id)}
            <tr data-testid="job-row">
              <td>{when(job.created_at)}</td>
              <td>{label(job)}</td>
              <td>
                <span class={`badge badge-${TONE[job.status]}`}>{job.status}</span>
                {#if job.attempts > 1}<span class="meta">{job.attempts} attempts</span>{/if}
                {#if job.error_message}<div class="meta error-line">{job.error_message}</div>{/if}
              </td>
              <td>
                {#if job.id in decrypted}
                  <span class="value" data-testid="job-value">{decrypted[job.id]}</span>
                {:else if job.status === 'completed' && job.compressed_results}
                  <span class="meta">{size(job.result_bytes)} · compressed, decrypt with the SDK</span>
                {:else if job.status === 'completed' && job.key_id && job.key_id === fheSession.unlockedKeyId}
                  <button type="button" class="btn-secondary btn-sm" onclick={() => decrypt(job)}>Decrypt</button>
                  <span class="meta">{size(job.result_bytes)}</span>
                {:else if job.status === 'completed'}
                  <span class="meta">
                    {size(job.result_bytes)} ·
                    <a href={resolve('/keys')}>unlock its key</a> to decrypt
                  </span>
                {:else}
                  <span class="meta">—</span>
                {/if}
              </td>
              <td>
                {#if job.status !== 'processing'}
                  <button type="button" class="btn-ghost btn-sm" onclick={() => remove(job)} aria-label={`Delete job from ${when(job.created_at)}`}>
                    Delete
                  </button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if nextCursor}
      <button type="button" class="btn-secondary load-more" onclick={() => load(nextCursor ?? undefined)} disabled={loading}>
        {loading ? 'Loading…' : 'Load more'}
      </button>
    {/if}
  {/if}
</div>

<style>
  .page { display: flex; flex-direction: column; gap: 1rem; }
  .title-row { display: flex; align-items: center; justify-content: space-between; }
  .lede, .hint { color: var(--text-secondary); font-size: 0.875rem; line-height: 1.5; }
  .table-wrap { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius); }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.65rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); }
  tbody tr:last-child td { border-bottom: none; }
  .meta { font-size: 0.775rem; color: var(--text-secondary); margin-left: 0.35rem; }
  .error-line { margin: 0.25rem 0 0; color: #fca5a5; }
  .value { font-family: var(--font-mono); font-size: 1rem; color: var(--success); }
  .load-more { align-self: center; }
  a { color: #a5b4fc; }
  .visually-hidden {
    position: absolute; width: 1px; height: 1px; overflow: hidden;
    clip: rect(0 0 0 0); white-space: nowrap;
  }
</style>
