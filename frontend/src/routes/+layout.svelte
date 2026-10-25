<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { asset, resolve } from '$app/paths';
  import { userStore } from '#lib/stores.js';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { auth } from '#lib/api.js';

  function isTokenExpired(token: string): boolean {
    try {
      const [, p] = token.split('.');
      const payload = JSON.parse(atob(p));
      return typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now();
    } catch { return true; }
  }

  onMount(() => {
    // An expired access token is fine while a refresh token exists: the API client
    // refreshes it on the first 401.
    const token = localStorage.getItem('token');
    const hasSession = (token && !isTokenExpired(token)) || localStorage.getItem('refresh_token');
    if (!hasSession) {
      localStorage.removeItem('token');
      localStorage.removeItem('refresh_token');
      userStore.set(null);
      if (page.url.pathname !== resolve('/login')) goto(resolve('/login'));
    }
  });

  async function logout() {
    const refreshToken = localStorage.getItem('refresh_token');
    if (refreshToken) {
      try { await auth.logout(refreshToken); } catch {}
    }
    localStorage.removeItem('token');
    localStorage.removeItem('refresh_token');
    userStore.set(null);
    goto(resolve('/login'));
  }
</script>

<!-- Read `page` in the template, not in a `$:` statement: legacy reactive
     statements do not track `$app/state`, so the shell would never update. -->
{#if page.url.pathname === resolve('/login')}
  <slot />
{:else}
  <div class="app">
    <header class="topbar">
      <a class="brand" href={resolve('/dashboard')}>
        <img src={asset('logo.svg')} alt="HEaaS" class="brand-logo" />
      </a>
      <nav class="topbar-right">
        {#if $userStore}
          <span class="user-chip">{$userStore.email}</span>
          <a class="btn-ghost" href={resolve('/account')}>Account</a>
          <button class="btn-ghost" on:click={logout}>Sign out</button>
        {:else}
          <a class="btn-ghost" href={resolve('/login')}>Sign in</a>
        {/if}
      </nav>
    </header>
    <main class="page-content">
      <slot />
    </main>
  </div>
{/if}

<style>
  .app { min-height: 100vh; display: flex; flex-direction: column; }

  .topbar {
    position: sticky; top: 0; z-index: 100;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 1.75rem; height: 58px;
    background: rgba(8, 11, 20, 0.92);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid var(--border);
  }

  .brand { display: flex; align-items: center; text-decoration: none; }
  .brand-logo { height: 38px; width: auto; display: block; }

  .topbar-right { display: flex; align-items: center; gap: 0.5rem; }
  .user-chip {
    font-size: 0.8rem; color: var(--text-secondary);
    padding: 0.2rem 0.6rem;
    background: var(--border);
    border-radius: 999px;
    max-width: 200px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }

  .page-content {
    flex: 1;
    padding: 2rem 1.5rem;
    max-width: 860px;
    margin: 0 auto;
    width: 100%;
  }

  @media (max-width: 600px) {
    .topbar { padding: 0 1rem; }
    .page-content { padding: 1.25rem 1rem; }
    .user-chip { display: none; }
  }
</style>
