<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { base } from '$app/paths';
  import { userStore } from '$lib/stores';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';

  function isTokenExpired(token: string): boolean {
    try {
      const [, p] = token.split('.');
      const payload = JSON.parse(atob(p));
      return typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now();
    } catch { return true; }
  }

  onMount(() => {
    const token = localStorage.getItem('token');
    if (!token || isTokenExpired(token)) {
      localStorage.removeItem('token');
      userStore.set(null);
      if ($page.url.pathname !== `${base}/login`) goto(`${base}/login`);
    }
  });

  function logout() {
    localStorage.removeItem('token');
    userStore.set(null);
    goto(`${base}/login`);
  }

  $: isAuthPage = $page.url.pathname === `${base}/login`;
</script>

{#if isAuthPage}
  <slot />
{:else}
  <div class="app">
    <header class="topbar">
      <a class="brand" href="{base}/dashboard">
        <span class="brand-mark">⟨HE⟩</span>
        <span class="brand-text">HEaaS</span>
        <span class="badge badge-indigo">Beta</span>
      </a>
      <nav class="topbar-right">
        {#if $userStore}
          <span class="user-chip">{$userStore.email}</span>
          <button class="btn-ghost" on:click={logout}>Sign out</button>
        {:else}
          <a class="btn-ghost" href="{base}/login">Sign in</a>
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
    padding: 0 1.5rem; height: 54px;
    background: rgba(8, 11, 20, 0.80);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border-bottom: 1px solid var(--border);
  }

  .brand {
    display: flex; align-items: center; gap: 0.6rem;
    text-decoration: none;
  }
  .brand-mark {
    font-family: var(--font-mono);
    font-size: 0.9375rem; font-weight: 500;
    color: var(--accent);
    background: var(--accent-glow);
    padding: 0.2rem 0.45rem;
    border-radius: 5px;
    border: 1px solid rgba(99,102,241,0.35);
    letter-spacing: -0.04em;
  }
  .brand-text {
    font-weight: 700; font-size: 0.9375rem;
    color: var(--text-primary); letter-spacing: -0.02em;
  }

  .topbar-right { display: flex; align-items: center; gap: 0.5rem; }
  .user-chip {
    font-size: 0.8125rem; color: var(--text-secondary);
    padding: 0.25rem 0.625rem;
    background: var(--border);
    border-radius: 999px;
    max-width: 200px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }

  .page-content {
    flex: 1;
    padding: 2.5rem 1.5rem;
    max-width: 820px;
    margin: 0 auto;
    width: 100%;
  }

  @media (max-width: 600px) {
    .page-content { padding: 1.5rem 1rem; }
    .user-chip { display: none; }
  }
</style>
