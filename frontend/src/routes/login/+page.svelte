<script lang="ts">
  import { goto } from '$app/navigation';
  import { auth } from '$lib/api';
  import { userStore } from '$lib/stores';

  let email = '', password = '', error = '', loading = false, isLogin = true;

  async function handleSubmit() {
    loading = true; error = '';
    try {
      const res = isLogin ? await auth.login(email, password) : await auth.register(email, password);
      localStorage.setItem('token', res.data.token);
      userStore.set(res.data.user);
      goto('/dashboard');
    } catch (e: any) {
      error = e.response?.data?.message || (isLogin ? 'Login failed' : 'Registration failed');
    } finally { loading = false; }
  }
</script>

<div class="container">
  <h1>{isLogin ? 'HE SaaS Login' : 'Create an Account'}</h1>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <form on:submit|preventDefault={handleSubmit}>
    <label for="email">Email</label>
    <input id="email" type="email" bind:value={email} placeholder="email@example.com" required />
    <label for="password">Password</label>
    <input id="password" type="password" bind:value={password} placeholder="••••••••" required />
    <button type="submit" disabled={loading} class="btn-primary">
      {loading ? 'Processing...' : (isLogin ? 'Login' : 'Register')}
    </button>
  </form>
  <p class="toggle-text">
    {isLogin ? "Don't have an account?" : "Already have an account?"}
    <button class="btn-link" on:click={() => isLogin = !isLogin} type="button">
      {isLogin ? 'Register' : 'Login'}
    </button>
  </p>
</div>

<style>
  .container { max-width: 400px; margin: 0 auto; padding: 2rem; }
  label { display: block; margin-bottom: 0.25rem; font-size: 0.875rem; font-weight: 500; }
  .btn-primary { width: 100%; padding: 0.5rem; margin-top: 0.5rem; background: var(--accent); color: white; }
  .btn-primary:hover { background: var(--accent-hover); }
  .toggle-text { margin-top: 1.5rem; text-align: center; font-size: 0.875rem; color: var(--text-secondary); }
  .btn-link { background: none; border: none; color: var(--accent); cursor: pointer; text-decoration: underline; padding: 0; font-size: inherit; }
</style>