<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { resolve } from '$app/paths';

  onMount(() => {
    if (localStorage.getItem('token') || localStorage.getItem('refresh_token')) {
      goto(resolve('/dashboard'));
    } else {
      goto(resolve('/login'));
    }
  });
</script>

<div class="loading">Redirecting...</div>

<style>
  .loading { display: flex; justify-content: center; align-items: center; height: 50vh; color: var(--text-secondary); }
</style>
