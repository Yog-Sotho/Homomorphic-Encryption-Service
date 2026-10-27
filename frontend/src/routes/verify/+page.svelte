<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { resolve } from '$app/paths';
  import { auth, errorMessage } from '#lib/api.js';

  let status: 'working' | 'failed' = 'working';
  let error = '';

  onMount(async () => {
    // The token is in the fragment, which never reaches a server; drop it from
    // the address bar and history before using it.
    const token = new URLSearchParams(window.location.hash.slice(1)).get('token');
    history.replaceState(history.state, '', window.location.pathname);
    if (!token) {
      status = 'failed';
      error = 'This verification link is incomplete.';
      return;
    }
    try {
      await auth.verifyEmail(token);
      goto(resolve('/dashboard'));
    } catch (e) {
      status = 'failed';
      error = errorMessage(e, 'Verification failed.');
    }
  });
</script>

<div class="container">
  <h1>Verify your email</h1>
  {#if status === 'working'}
    <p role="status">Verifying…</p>
  {:else}
    <p class="error" role="alert">{error}</p>
    <p>Links expire after 24 hours and work once. Sign in to request a new one.</p>
    <a class="btn-primary" href={resolve('/login')}>Go to sign-in</a>
  {/if}
</div>

<style>
  .container { max-width: 420px; margin: 4rem auto; padding: 2rem; }
  .error { color: var(--danger, #ef4444); }
  .btn-primary { display: inline-block; margin-top: 1rem; text-decoration: none; }
</style>
