<script lang="ts">
  import { errorMessage } from '#lib/api.js';
  import { isProtected } from '#lib/fhe/keystore.js';
  import { fheSession, type KeyEntry } from '#lib/fhe/session.svelte.js';
  import { PASSPHRASE_MIN_LENGTH, WrongPassphraseError } from '#lib/fhe/vault.js';
  import type { StoredClientKey } from '#lib/fhe/keystore.js';

  let {
    entry,
    onunlocked
  }: { entry: KeyEntry & { local: StoredClientKey }; onunlocked?: () => void } = $props();

  // Keys stored before passphrases existed get one now.
  const legacy = $derived(!isProtected(entry.local));
  const fieldId = $derived(`passphrase-${entry.server.id}`);

  let passphrase = $state('');
  let confirm = $state('');
  let busy = $state(false);
  let error = $state('');

  const valid = $derived(
    legacy ? passphrase.length >= PASSPHRASE_MIN_LENGTH && passphrase === confirm : passphrase.length > 0
  );

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    busy = true;
    error = '';
    try {
      await fheSession.unlock(entry, passphrase);
      passphrase = '';
      confirm = '';
      onunlocked?.();
    } catch (e) {
      error = e instanceof WrongPassphraseError ? 'Wrong passphrase.' : errorMessage(e, 'Could not unlock the key.');
    } finally {
      busy = false;
    }
  }
</script>

<form class="unlock" onsubmit={submit}>
  {#if legacy}
    <p class="hint">
      This key was stored before passphrases existed and is not protected. Choose a passphrase to
      encrypt it in this browser (at least {PASSPHRASE_MIN_LENGTH} characters).
    </p>
  {/if}
  <label for={fieldId}>{legacy ? 'New passphrase' : 'Passphrase'}</label>
  <input
    id={fieldId}
    type="password"
    autocomplete={legacy ? 'new-password' : 'current-password'}
    bind:value={passphrase}
    required
  />
  {#if legacy}
    <label for={`${fieldId}-confirm`}>Repeat the passphrase</label>
    <input id={`${fieldId}-confirm`} type="password" autocomplete="new-password" bind:value={confirm} required />
  {/if}
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <button type="submit" class="btn-primary" disabled={busy || !valid}>
    {#if busy}<span class="spinner" aria-hidden="true"></span> Unlocking…{:else}{legacy ? 'Protect and unlock' : 'Unlock key'}{/if}
  </button>
</form>

<style>
  .unlock { display: flex; flex-direction: column; gap: 0.25rem; max-width: 26rem; }
  .hint { font-size: 0.8125rem; color: var(--text-secondary); margin-bottom: 0.5rem; }
  .btn-primary { align-self: flex-start; display: inline-flex; gap: 0.5rem; align-items: center; }
</style>
