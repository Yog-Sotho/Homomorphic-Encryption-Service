<script lang="ts">
  import '../app.css';
  import '@fontsource-variable/inter';
  import '@fontsource-variable/jetbrains-mono';
  import type { Snippet } from 'svelte';
  import { onMount } from 'svelte';
  import { asset, resolve } from '$app/paths';
  import { goto } from '$app/navigation';
  import { page } from '$app/state';
  import { session } from '#lib/api.js';
  import { fheSession } from '#lib/fhe/session.svelte.js';
  import { userStore } from '#lib/stores.js';

  let { children }: { children: Snippet } = $props();

  /** Pages that work signed out and render without the app shell. */
  const PUBLIC: string[] = [resolve('/login'), resolve('/verify'), resolve('/reset')];
  const NAV = [
    { href: resolve('/dashboard'), label: 'Dashboard' },
    { href: resolve('/keys'), label: 'Keys' },
    { href: resolve('/jobs'), label: 'Jobs' },
    { href: resolve('/account'), label: 'Account' }
  ];

  const isPublic = $derived(PUBLIC.includes(page.url.pathname));

  onMount(async () => {
    if (isPublic) return;
    // The session lives in an HttpOnly cookie; this turns it into an access token.
    if (!(await session.restore())) goto(resolve('/login'));
  });

  async function logout() {
    fheSession.reset();
    await session.end().catch(() => {});
    goto(resolve('/login'));
  }
</script>

{#if isPublic}
  <main>{@render children()}</main>
{:else}
  <div class="app">
    <header class="topbar">
      <a class="brand" href={resolve('/dashboard')}>
        <img src={asset('logo.svg')} alt="HE Engine home" class="brand-logo" />
      </a>
      <nav class="nav" aria-label="Main">
        {#each NAV as item (item.href)}
          <a
            class="nav-link"
            href={item.href}
            aria-current={page.url.pathname === item.href ? 'page' : undefined}
          >
            {item.label}
          </a>
        {/each}
      </nav>
      <div class="topbar-right">
        {#if $userStore}
          <span class="user-chip">{$userStore.email}</span>
          <button type="button" class="btn-ghost" onclick={logout}>Sign out</button>
        {:else}
          <a class="btn-ghost" href={resolve('/login')}>Sign in</a>
        {/if}
      </div>
    </header>
    <main class="page-content">
      {@render children()}
    </main>
  </div>
{/if}

<style>
  .app { min-height: 100vh; display: flex; flex-direction: column; }

  .topbar {
    position: sticky; top: 0; z-index: 100;
    display: flex; align-items: center; gap: 0.5rem;
    padding: 0 1.75rem; height: 58px;
    background: rgba(8, 11, 20, 0.92);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-bottom: 1px solid var(--border);
  }

  .brand { display: flex; align-items: center; text-decoration: none; }
  .brand-logo { height: 38px; width: auto; display: block; }

  .nav { display: flex; gap: 0.25rem; margin: 0 auto 0 1.5rem; }
  .nav-link {
    color: var(--text-secondary); text-decoration: none; font-size: 0.875rem;
    padding: 0.35rem 0.7rem; border-radius: var(--radius-sm);
  }
  .nav-link:hover { color: var(--text-primary); background: var(--border); }
  .nav-link[aria-current='page'] { color: var(--text-primary); background: var(--surface-elevated); }

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

  @media (max-width: 700px) {
    .topbar { padding: 0 1rem; }
    .brand-logo { height: 30px; }
    .nav { margin-left: 0.5rem; }
    .nav-link { padding: 0.35rem 0.45rem; }
    .page-content { padding: 1.25rem 1rem; }
    .user-chip { display: none; }
  }
</style>
