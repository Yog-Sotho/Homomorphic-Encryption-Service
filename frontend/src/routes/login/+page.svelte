<script lang="ts">
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import { auth } from '$lib/api';
  import { userStore } from '$lib/stores';

  let email = '', password = '', error = '', loading = false, isLogin = true, showPassword = false;

  async function handleSubmit() {
    loading = true; error = '';
    try {
      if (isLogin) {
        const res = await auth.login(email, password);
        localStorage.setItem('token', res.data.token);
        if (res.data.refresh_token) localStorage.setItem('refresh_token', res.data.refresh_token);
        userStore.set(res.data.user);
        goto(`${base}/dashboard`);
      } else {
        await auth.register(email, password);
        isLogin = true;
        error = 'Account created! Please sign in.';
      }
    } catch (e: any) {
      error = e.response?.data?.message || (isLogin ? 'Login failed' : 'Registration failed');
    } finally { loading = false; }
  }
</script>

<div class="container">
  <h1>{isLogin ? 'HE SaaS Login' : 'Create an Account'}</h1>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <form on:submit|preventDefault={handleSubmit}>
    <label for="email">Email <span class="required" aria-hidden="true">*</span></label>
    <input
      id="email"
      type="email"
      bind:value={email}
      placeholder="email@example.com"
      autocomplete="email"
      required
    />

    <label for="password">Password <span class="required" aria-hidden="true">*</span></label>
    <div class="password-wrapper">
      <input
        id="password"
        type={showPassword ? 'text' : 'password'}
        bind:value={password}
        placeholder="••••••••"
        autocomplete={isLogin ? 'current-password' : 'new-password'}
        required
      />
      <button
        type="button"
        class="toggle-password"
        on:click={() => (showPassword = !showPassword)}
        aria-label={showPassword ? 'Hide password' : 'Show password'}
        aria-pressed={showPassword}
      >
        {showPassword ? 'HIDE' : 'SHOW'}
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
  .container { max-width: 420px; margin: 3rem auto; padding: 2rem; }
  h1 { margin-bottom: 1.25rem; font-size: 1.375rem; text-align: center; }
  .toggle-text { margin-top: 1.5rem; text-align: center; font-size: 0.875rem; color: var(--text-secondary); }
  .btn-link { background: none; border: none; color: var(--accent); cursor: pointer; text-decoration: underline; padding: 0; font-size: inherit; }

  .password-wrapper { position: relative; margin-bottom: 1rem; }
  .password-wrapper input { padding-right: 3.5rem; margin-bottom: 0; }
  .toggle-password {
    position: absolute;
    right: 0.75rem;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    color: var(--accent);
    font-size: 0.75rem;
    font-weight: 700;
    padding: 0.25rem;
    cursor: pointer;
  }
</style>
