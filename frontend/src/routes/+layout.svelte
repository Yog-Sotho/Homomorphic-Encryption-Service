<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { base } from '$app/paths';
  import { userStore } from '$lib/stores';
  import { goto } from '$app/navigation';
  import { page } from '$app/stores';

  function isTokenExpired(token: string): boolean {
    try {
      const [, payloadB64] = token.split('.');
      const payload = JSON.parse(atob(payloadB64));
      return typeof payload.exp !== 'number' || payload.exp * 1000 < Date.now();
    } catch {
      return true;
    }
  }

  onMount(() => {
    const token = localStorage.getItem('token');
    if (!token || isTokenExpired(token)) {
      localStorage.removeItem('token');
      userStore.set(null);
      if ($page.url.pathname !== `${base}/login`) {
        goto(`${base}/login`);
      }
    }
  });
</script>

<div class="layout">
  <nav class="navbar">
    <a class="nav-brand" href="{base}/dashboard">HEaaS Dashboard</a>
    <div class="nav-links">
      {#if $userStore}
        <a href="{base}/dashboard">Dashboard</a>
        <button class="btn-secondary" on:click={() => {
          localStorage.removeItem('token');
          userStore.set(null);
          goto(`${base}/login`);
        }}>Logout</button>
      {:else}
        <a href="{base}/login">Login</a>
      {/if}
    </div>
  </nav>
  <main class="container">
    <slot />
  </main>
</div>

<style>
  .layout { min-height: 100vh; display: flex; flex-direction: column; }
  .navbar {
    display: flex; justify-content: space-between; align-items: center;
    padding: 1rem 2rem; background: var(--bg-secondary); border-bottom: 1px solid var(--border);
  }
  .nav-brand { font-weight: 700; font-size: 1.25rem; color: var(--accent); text-decoration: none; }
  .nav-brand:hover { opacity: 0.85; }
  .nav-links { display: flex; gap: 1rem; align-items: center; }
  .nav-links a { color: var(--text-secondary); text-decoration: none; font-weight: 500; }
  .nav-links a:hover { color: var(--text-primary); }
  .container { flex: 1; padding: 2rem; max-width: 1200px; margin: 0 auto; width: 100%; }
</style>
