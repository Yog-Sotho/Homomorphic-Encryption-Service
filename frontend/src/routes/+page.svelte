<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { userStore } from '$lib/stores';

  onMount(() => {
    const token = localStorage.getItem('token');
    if (token) {
      goto('/dashboard');
    } else {
      goto('/login');
    }
  });
</script>

<div class="loading">Redirecting...</div>

<style>
  .loading { display: flex; justify-content: center; align-items: center; height: 50vh; color: var(--text-secondary); }
</style>
