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
        <img src="{base}/logo.svg" alt="HEaaS" class="brand-logo" />
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
    padding: 0 1.75rem; height: 52px;
    background: rgba(8, 11, 20, 0.92);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid var(--border);
  }

  .brand { display: flex; align-items: center; text-decoration: none; }
  .brand-logo { height: 28px; width: auto; display: block; }

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
