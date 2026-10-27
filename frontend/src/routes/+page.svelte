<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { resolve } from '$app/paths';
  import { session } from '#lib/api.js';

  onMount(async () => {
    goto(resolve((await session.restore()) ? '/dashboard' : '/login'));
  });
</script>

<div class="loading">Redirecting...</div>

<style>
  .loading { display: flex; justify-content: center; align-items: center; height: 50vh; color: var(--text-secondary); }
</style>
