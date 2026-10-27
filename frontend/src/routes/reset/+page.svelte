<script lang="ts">
  import { onMount } from 'svelte';
  import { resolve } from '$app/paths';
  import { auth, errorMessage } from '#lib/api.js';
  import { PASSWORD_REQUIREMENTS, isStrongPassword } from '#lib/password-policy.js';

  let token = $state('');
  let password = $state('');
  let confirm = $state('');
  let error = $state('');
  let loading = $state(false);
  let done = $state(false);

  const mismatch = $derived(confirm.length > 0 && password !== confirm);

  onMount(() => {
    // Keep the token in memory only; remove it from the address bar and history.
    token = new URLSearchParams(window.location.hash.slice(1)).get('token') ?? '';
    history.replaceState(history.state, '', window.location.pathname);
    if (!token) error = 'This reset link is incomplete. Request a new one from the sign-in page.';
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    loading = true;
    error = '';
    try {
      await auth.resetPassword(token, password);
      done = true;
      token = '';
    } catch (e) {
      error = errorMessage(e, 'Could not reset the password.');
    } finally {
      loading = false;
    }
  }
</script>

<svelte:head><title>Reset password · HEaaS</title></svelte:head>

<div class="container">
  <h1>Choose a new password</h1>
  {#if done}
    <p role="status">Password reset. You were signed out everywhere.</p>
    <a class="btn-primary" href={resolve('/login')}>Sign in</a>
  {:else}
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    {#if token}
      <form onsubmit={submit}>
        <label for="new-password">New password</label>
        <input id="new-password" type="password" autocomplete="new-password" bind:value={password} required />
        <label for="confirm-password">Repeat it</label>
        <input id="confirm-password" type="password" autocomplete="new-password" bind:value={confirm} required />
        <p class="hint">{PASSWORD_REQUIREMENTS}</p>
        {#if mismatch}<p class="error">The passwords do not match.</p>{/if}
        <button class="btn-primary" type="submit" disabled={loading || !isStrongPassword(password) || password !== confirm}>
          {loading ? 'Saving…' : 'Set password'}
        </button>
      </form>
    {:else}
      <a class="btn-primary" href={resolve('/login')}>Go to sign-in</a>
    {/if}
  {/if}
</div>

<style>
  .container { max-width: 420px; margin: 4rem auto; padding: 2rem; }
  form { display: flex; flex-direction: column; gap: 0.5rem; }
  .hint { color: var(--text-secondary); font-size: 0.85rem; }
  .btn-primary { display: inline-block; margin-top: 1rem; text-decoration: none; }
</style>
