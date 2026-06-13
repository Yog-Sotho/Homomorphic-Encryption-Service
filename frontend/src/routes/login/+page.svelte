<script lang="ts">
  import { goto } from '$app/navigation';
  import { auth } from '$lib/api';
  import { userStore } from '$lib/stores';

  let email = '', password = '', error = '', loading = false, isLogin = true;
  let showPassword = false;

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
    <div class="password-wrapper">
      <input id="password" type={showPassword ? 'text' : 'password'} bind:value={password} placeholder="••••••••" required />
      <button
        type="button"
        class="toggle-password"
        on:click={() => showPassword = !showPassword}
        aria-label={showPassword ? 'Hide password' : 'Show password'}
      >
        {#if showPassword}
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-eye-off"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"/><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.52 13.52 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"/><line x1="2" x2="22" y1="2" y2="22"/></svg>
        {:else}
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-eye"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0z"/><circle cx="12" cy="12" r="3"/></svg>
        {/if}
      </button>
    </div>
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
  .toggle-text { margin-top: 1.5rem; text-align: center; font-size: 0.875rem; color: var(--text-secondary); }
  .btn-link { background: none; border: none; color: var(--accent); cursor: pointer; text-decoration: underline; padding: 0; font-size: inherit; }
  .password-wrapper { position: relative; margin-bottom: 0.5rem; }
  .password-wrapper input { margin-bottom: 0; padding-right: 2.5rem; }
  .toggle-password {
    position: absolute; right: 0.25rem; top: 50%; transform: translateY(-50%);
    background: none; border: none; padding: 0.5rem; color: var(--text-secondary);
    display: flex; align-items: center; justify-content: center;
  }
  .toggle-password:hover { color: var(--text-primary); }
</style>
