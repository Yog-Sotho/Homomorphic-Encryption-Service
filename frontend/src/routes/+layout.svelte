<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { userStore } from '$lib/stores';
  import { goto } from '$app/navigation';

  onMount(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      userStore.set(null);
    }
  });
</script>

<div class="layout">
  <nav class="navbar">
    <div class="nav-brand">HEaaS Dashboard</div>
    <div class="nav-links">
      {#if $userStore}
        <a href="/dashboard">Dashboard</a>
        <button class="btn-secondary" on:click={() => {
          localStorage.removeItem('token');
          userStore.set(null);
          goto('/login');
        }}>Logout</button>
      {:else}
        <a href="/login">Login</a>
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
  .nav-brand { font-weight: 700; font-size: 1.25rem; color: var(--accent); }
  .nav-links { display: flex; gap: 1rem; align-items: center; }
  .nav-links a { color: var(--text-secondary); text-decoration: none; font-weight: 500; }
  .nav-links a:hover { color: var(--text-primary); }
  .btn-secondary {
    background: transparent; border: 1px solid var(--border); color: var(--text-primary);
    padding: 0.5rem 1rem; border-radius: var(--radius);
  }
  .btn-secondary:hover { background: var(--border); }
  .container { flex: 1; padding: 2rem; max-width: 1200px; margin: 0 auto; width: 100%; }
</style>
