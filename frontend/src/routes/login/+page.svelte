<script lang="ts">
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import { auth } from '$lib/api';
  import { userStore } from '$lib/stores';

  let email = '', password = '', error = '', loading = false, isLogin = true;

  $: passwordHint = !isLogin && password.length > 0 && !isValidPassword(password);

  function isValidPassword(p: string): boolean {
    return p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p);
  }

  async function handleSubmit() {
    loading = true; error = '';
    try {
      const res = isLogin ? await auth.login(email, password) : await auth.register(email, password);
      localStorage.setItem('token', res.data.token);
      userStore.set(res.data.user);
      goto(`${base}/dashboard`);
    } catch (e: any) {
      error = e.response?.data?.message || (isLogin ? 'Login failed' : 'Registration failed');
    } finally { loading = false; }
  }
</script>

<div class="container">
  <h1>{isLogin ? 'Sign In' : 'Create Account'}</h1>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <form on:submit|preventDefault={handleSubmit}>
    <label for="email">Email</label>
    <input id="email" type="email" bind:value={email} placeholder="you@example.com" required autocomplete="email" />

    <label for="password">Password</label>
    <input id="password" type="password" bind:value={password} placeholder="••••••••" required
      autocomplete={isLogin ? 'current-password' : 'new-password'} />

    {#if passwordHint}
      <ul class="hint" aria-live="polite">
        <li class:ok={password.length >= 8}>At least 8 characters</li>
        <li class:ok={/[A-Z]/.test(password)}>One uppercase letter</li>
        <li class:ok={/[a-z]/.test(password)}>One lowercase letter</li>
        <li class:ok={/[0-9]/.test(password)}>One digit</li>
      </ul>
    {/if}

    <button type="submit" disabled={loading || (!isLogin && password.length > 0 && !isValidPassword(password))} class="btn-primary">
      {loading ? 'Processing…' : (isLogin ? 'Sign In' : 'Create Account')}
    </button>
  </form>
  <p class="toggle-text">
    {isLogin ? "No account?" : "Already have an account?"}
    <button class="btn-link" on:click={() => { isLogin = !isLogin; error = ''; }} type="button">
      {isLogin ? 'Register' : 'Sign In'}
    </button>
  </p>
</div>

<style>
  .container { max-width: 420px; margin: 3rem auto; padding: 2rem; }
  h1 { margin-bottom: 1.5rem; font-size: 1.5rem; }
  .toggle-text { margin-top: 1.5rem; text-align: center; font-size: 0.875rem; color: var(--text-secondary); }
  .btn-link { background: none; border: none; color: var(--accent); cursor: pointer; text-decoration: underline; padding: 0; font-size: inherit; }
  .hint {
    list-style: none; padding: 0.5rem 0.75rem; margin: 0.25rem 0 0.75rem;
    background: var(--bg-secondary); border-radius: 6px; font-size: 0.8rem;
    display: flex; flex-direction: column; gap: 0.2rem;
  }
  .hint li { color: var(--text-secondary); }
  .hint li::before { content: '✗ '; color: #ef4444; }
  .hint li.ok { color: #22c55e; }
  .hint li.ok::before { content: '✓ '; }
</style>
