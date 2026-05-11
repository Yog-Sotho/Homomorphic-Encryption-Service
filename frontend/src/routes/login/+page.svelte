<script lang="ts">
  import { goto } from '$app/navigation';
  import { auth } from '$lib/api';
  import { userStore } from '$lib/stores';

  let email = '';
  let password = '';
  let error = '';
  let loading = false;

  async function handleLogin() {
    loading = true;
    error = '';
    try {
      const res = await auth.login(email, password);
      localStorage.setItem('token', res.data.token);
      userStore.set(res.data.user);
      goto('/dashboard');
    } catch (e: any) {
      error = e.response?.data?.message || 'Login failed';
    } finally {
      loading = false;
    }
  }

  async function handleRegister() {
    loading = true;
    error = '';
    try {
      const res = await auth.register(email, password);
      localStorage.setItem('token', res.data.token);
      userStore.set(res.data.user);
      goto('/dashboard');
    } catch (e: any) {
      error = e.response?.data?.message || 'Registration failed';
    } finally {
      loading = false;
    }
  }
</script>

<div class="container">
  <h1>HE SaaS Login</h1>
  {#if error}
    <p class="error">{error}</p>
  {/if}
  <form on:submit|preventDefault={handleLogin}>
    <input type="email" bind:value={email} placeholder="Email" required />
    <input type="password" bind:value={password} placeholder="Password" required />
    <button type="submit" disabled={loading}>{loading ? 'Loading...' : 'Login'}</button>
  </form>
  <button on:click={handleRegister} disabled={loading}>Register</button>
</div>

<style>
  .container { max-width: 400px; margin: 0 auto; padding: 2rem; }
  input { display: block; width: 100%; margin-bottom: 1rem; padding: 0.5rem; }
  button { width: 100%; padding: 0.5rem; margin-top: 0.5rem; }
  .error { color: red; }
</style>