<script lang="ts">
  import { onMount } from 'svelte';
  import { errorMessage, he } from '#lib/api.js';
  import UnlockForm from '#lib/components/UnlockForm.svelte';
  import { keyFileName, toKeyFile } from '#lib/fhe/keyfile.js';
  import { isProtected, type StoredClientKey } from '#lib/fhe/keystore.js';
  import { fheSession, loadKeyOverview, type KeyEntry, type KeyOverview } from '#lib/fhe/session.svelte.js';
  import { PASSPHRASE_MIN_LENGTH, WrongPassphraseError } from '#lib/fhe/vault.js';

  type Panel = { keyId: string; kind: 'unlock' | 'import' | 'delete' } | null;

  let overview = $state<KeyOverview | null>(null);
  let maxKeys = $state(2);
  let loadError = $state('');
  let error = $state('');
  let panel = $state<Panel>(null);

  // Generating
  let passphrase = $state('');
  let confirmPassphrase = $state('');
  let generating = $state<'keys' | 'upload' | null>(null);

  // Importing
  let importFile = $state<File | null>(null);
  let importPassphrase = $state('');
  let importing = $state(false);

  // Checked in the browser only: server-side rendering has no Worker.
  let supported = $state(true);
  const atLimit = $derived((overview?.entries.length ?? 0) >= maxKeys);
  const passphraseOk = $derived(
    passphrase.length >= PASSPHRASE_MIN_LENGTH && passphrase === confirmPassphrase
  );

  async function refresh() {
    try {
      overview = await loadKeyOverview();
      loadError = '';
    } catch (e) {
      loadError = errorMessage(e, 'Could not load your keys.');
    }
  }

  onMount(async () => {
    supported = fheSession.supported;
    await refresh();
    try {
      maxKeys = (await he.params()).max_keys_per_user;
    } catch {
      // Keep the default limit for the hint; the server enforces the real one.
    }
  });

  async function generate(event: SubmitEvent) {
    event.preventDefault();
    error = '';
    generating = 'keys';
    try {
      await fheSession.generate(passphrase, () => (generating = 'upload'));
      passphrase = '';
      confirmPassphrase = '';
      await refresh();
    } catch (e) {
      error = errorMessage(e, 'Key generation failed.');
    } finally {
      generating = null;
    }
  }

  function exportKey(local: StoredClientKey) {
    if (!isProtected(local)) return;
    const blob = new Blob([toKeyFile(local)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = keyFileName(local.keyId);
    link.click();
    // Revoke after the download has started.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function importKey(event: SubmitEvent) {
    event.preventDefault();
    if (!importFile || !overview) return;
    importing = true;
    error = '';
    try {
      const text = await importFile.text();
      await fheSession.importKeyFile(text, importPassphrase, overview.entries.map((e) => e.server));
      importPassphrase = '';
      importFile = null;
      panel = null;
      await refresh();
    } catch (e) {
      error = e instanceof WrongPassphraseError ? 'Wrong passphrase for this key file.' : errorMessage(e, 'Import failed.');
    } finally {
      importing = false;
    }
  }

  async function remove(keyId: string) {
    error = '';
    try {
      await fheSession.remove(keyId);
      panel = null;
      await refresh();
    } catch (e) {
      error = errorMessage(e, 'Could not delete the key.');
    }
  }

  async function forget(keyId: string) {
    await fheSession.forget(keyId);
    await refresh();
  }

  function toggle(keyId: string, kind: 'unlock' | 'import' | 'delete') {
    panel = panel?.keyId === keyId && panel.kind === kind ? null : { keyId, kind };
    error = '';
  }

  function status(entry: KeyEntry): { label: string; tone: 'green' | 'indigo' | 'red' } {
    if (fheSession.unlockedKeyId === entry.server.id) return { label: 'Unlocked', tone: 'green' };
    if (!entry.local) return { label: 'Not in this browser', tone: 'red' };
    if (!isProtected(entry.local)) return { label: 'Not protected', tone: 'red' };
    return { label: 'Locked', tone: 'indigo' };
  }

  function formatBytes(n: number): string {
    return `${(n / 1_000_000).toFixed(1)} MB`;
  }

  function formatDate(iso: string): string {
    const date = new Date(iso.endsWith('Z') || iso.includes('+') ? iso : `${iso}Z`);
    return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
  }
</script>

<svelte:head><title>Keys · HE Engine</title></svelte:head>

<div class="page">
  <h1>Encryption keys</h1>
  <p class="lede">
    Each key has two halves. The <strong>secret key</strong> encrypts and decrypts; it is made in
    this browser, encrypted with your passphrase, and never sent anywhere. The
    <strong>evaluation key</strong> (~60 MB) is uploaded so the server can compute on your ciphertexts
    without being able to read them.
  </p>

  {#if !supported}
    <p class="error" role="alert">
      In-browser encryption needs a cross-origin isolated page and Web Workers, which this browser
      or deployment does not provide.
    </p>
  {/if}
  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}

  <section class="card" aria-labelledby="new-key">
    <h2 id="new-key">Create a key</h2>
    {#if atLimit}
      <p class="hint">You have {maxKeys} keys, the most an account can register. Delete one first.</p>
    {:else}
      <form class="stack" onsubmit={generate}>
        <label for="new-passphrase">Passphrase</label>
        <input id="new-passphrase" type="password" autocomplete="new-password" bind:value={passphrase} required />
        <label for="new-passphrase-confirm">Repeat the passphrase</label>
        <input
          id="new-passphrase-confirm"
          type="password"
          autocomplete="new-password"
          bind:value={confirmPassphrase}
          required
        />
        <p class="hint">
          At least {PASSPHRASE_MIN_LENGTH} characters. It cannot be reset: without it (or after
          clearing this browser's data without a backup) the key and everything encrypted under it
          is lost. Export a backup once it is created.
        </p>
        <button type="submit" class="btn-primary" disabled={!supported || !passphraseOk || generating !== null}>
          {#if generating === 'keys'}
            <span class="spinner" aria-hidden="true"></span> Generating your key pair…
          {:else if generating === 'upload'}
            <span class="spinner" aria-hidden="true"></span> Uploading the evaluation key (~60 MB)…
          {:else}
            Generate encryption key
          {/if}
        </button>
      </form>
    {/if}
  </section>

  {#if overview}
    <section aria-labelledby="your-keys">
      <h2 id="your-keys" class="section-title">Your keys</h2>
      {#if overview.entries.length === 0}
        <p class="hint">No keys yet.</p>
      {/if}
      <ul class="key-list">
        {#each overview.entries as entry (entry.server.id)}
          {@const s = status(entry)}
          {@const id = entry.server.id}
          <li class="card key" data-testid="key-entry">
            <div class="key-head">
              <span class={`badge badge-${s.tone}`}>{s.label}</span>
              <code class="key-id" title={id}>{id}</code>
            </div>
            <p class="meta">
              Created {formatDate(entry.server.created_at)} · evaluation key {formatBytes(entry.server.size_bytes)}
            </p>
            <div class="actions">
              {#if fheSession.unlockedKeyId === id}
                <button type="button" class="btn-secondary btn-sm" onclick={() => fheSession.lock()}>Lock</button>
              {:else if entry.local}
                <button
                  type="button"
                  class="btn-secondary btn-sm"
                  aria-expanded={panel?.keyId === id && panel.kind === 'unlock'}
                  onclick={() => toggle(id, 'unlock')}
                >
                  {isProtected(entry.local) ? 'Unlock' : 'Protect with a passphrase'}
                </button>
              {:else}
                <button
                  type="button"
                  class="btn-secondary btn-sm"
                  aria-expanded={panel?.keyId === id && panel.kind === 'import'}
                  onclick={() => toggle(id, 'import')}
                >
                  Import backup
                </button>
              {/if}
              {#if entry.local && isProtected(entry.local)}
                {@const local = entry.local}
                <button type="button" class="btn-secondary btn-sm" onclick={() => exportKey(local)}>
                  Export backup
                </button>
              {/if}
              <button
                type="button"
                class="btn-ghost btn-sm"
                aria-expanded={panel?.keyId === id && panel.kind === 'delete'}
                onclick={() => toggle(id, 'delete')}
              >
                Delete
              </button>
            </div>

            {#if panel?.keyId === id && panel.kind === 'unlock' && entry.local}
              <UnlockForm entry={{ ...entry, local: entry.local }} onunlocked={() => { panel = null; refresh(); }} />
            {:else if panel?.keyId === id && panel.kind === 'import'}
              <form class="stack" onsubmit={importKey}>
                <label for={`file-${id}`}>Key backup file</label>
                <input
                  id={`file-${id}`}
                  type="file"
                  accept="application/json,.json"
                  onchange={(e) => (importFile = e.currentTarget.files?.[0] ?? null)}
                  required
                />
                <label for={`import-passphrase-${id}`}>Its passphrase</label>
                <input
                  id={`import-passphrase-${id}`}
                  type="password"
                  autocomplete="current-password"
                  bind:value={importPassphrase}
                  required
                />
                <button type="submit" class="btn-primary" disabled={!importFile || !importPassphrase || importing}>
                  {importing ? 'Importing…' : 'Import'}
                </button>
              </form>
            {:else if panel?.keyId === id && panel.kind === 'delete'}
              <div class="confirm" role="group" aria-label="Confirm deletion">
                <p>
                  Delete this key on the server and in this browser? Results encrypted under it can no
                  longer be decrypted unless you have a backup.
                </p>
                <button type="button" class="btn-danger btn-sm" onclick={() => remove(id)}>Delete key</button>
                <button type="button" class="btn-ghost btn-sm" onclick={() => (panel = null)}>Cancel</button>
              </div>
            {/if}
          </li>
        {/each}
      </ul>

      {#if overview.orphans.length > 0}
        <h2 class="section-title">Left in this browser</h2>
        <p class="hint">These secret keys belong to evaluation keys that no longer exist on the server.</p>
        <ul class="key-list">
          {#each overview.orphans as orphan (orphan.keyId)}
            <li class="card key">
              <code class="key-id">{orphan.keyId}</code>
              <button type="button" class="btn-ghost btn-sm" onclick={() => forget(orphan.keyId)}>Forget</button>
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  {/if}
</div>

<style>
  .page { display: flex; flex-direction: column; gap: 1rem; }
  .lede { color: var(--text-secondary); font-size: 0.9rem; line-height: 1.55; }
  .lede strong { color: var(--text-primary); }
  h2 { margin-bottom: 0.75rem; }
  .section-title { margin-top: 0.5rem; }
  .stack { display: flex; flex-direction: column; gap: 0.25rem; max-width: 26rem; }
  .stack .btn-primary { align-self: flex-start; display: inline-flex; gap: 0.5rem; align-items: center; }
  .hint { font-size: 0.8125rem; color: var(--text-secondary); margin-bottom: 0.75rem; line-height: 1.5; }
  .key-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 0.75rem; }
  .key { display: flex; flex-direction: column; gap: 0.6rem; }
  .card + .card { margin-top: 0; }
  .key-head { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
  .key-id { font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary); overflow-wrap: anywhere; }
  .meta { font-size: 0.8rem; color: var(--text-secondary); }
  .actions { display: flex; gap: 0.5rem; flex-wrap: wrap; }
  .confirm { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; font-size: 0.85rem; }
  .confirm p { flex-basis: 100%; color: var(--text-secondary); }
  /* Darker than --error so white text meets AA contrast. */
  .btn-danger {
    background: #b91c1c; color: #fff; border: none; border-radius: var(--radius-sm); cursor: pointer;
  }
  .btn-danger:hover { background: #991b1b; }
</style>
