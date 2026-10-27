<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { resolve } from '$app/paths';
  import { auth, errorMessage } from '#lib/api.js';
  import { isStrongPassword } from '#lib/password-policy.js';

  type Mode = 'login' | 'register' | 'forgot';

  let mode = $state<Mode>('login');
  let email = $state('');
  let password = $state('');
  let error = $state('');
  let notice = $state('');
  let loading = $state(false);
  let showPassword = $state(false);
  let registeredEmail = $state('');
  let providers = $state({ google: false, github: false });

  const passwordHint = $derived(mode === 'register' && password.length > 0 && !isStrongPassword(password));

  /** Reads and removes `#code=` / `#error=` / `#notice=` left by redirects. */
  function takeFragment(): URLSearchParams {
    const params = new URLSearchParams(window.location.hash.slice(1));
    if (window.location.hash) {
      history.replaceState(history.state, '', window.location.pathname + window.location.search);
    }
    return params;
  }

  onMount(async () => {
    const fragment = takeFragment();
    const code = fragment.get('code');
    if (code) {
      loading = true;
      try {
        await auth.exchange(code);
        goto(resolve('/dashboard'));
        return;
      } catch (e) {
        error = errorMessage(e, 'Sign-in failed. Please try again.');
      } finally {
        loading = false;
      }
    }
    error ||= fragment.get('error') ?? '';
    notice = fragment.get('notice') ?? '';
    try {
      providers = await auth.providers();
    } catch {
      // Social sign-in buttons stay hidden.
    }
  });

  function switchTo(next: Mode) {
    mode = next;
    error = '';
    notice = '';
  }

  async function handleSubmit(event: SubmitEvent) {
    event.preventDefault();
    loading = true;
    error = '';
    notice = '';
    try {
      if (mode === 'login') {
        await auth.login(email, password);
        goto(resolve('/dashboard'));
      } else if (mode === 'register') {
        const res = await auth.register(email, password);
        registeredEmail = email;
        mode = 'login';
        password = '';
        notice = res.message;
      } else {
        notice = (await auth.forgotPassword(email)).message;
      }
    } catch (e) {
      error = errorMessage(e, mode === 'login' ? 'Login failed' : 'Request failed');
    } finally {
      loading = false;
    }
  }

  async function resend() {
    loading = true;
    error = '';
    try {
      notice = (await auth.resendVerification(registeredEmail)).message;
    } catch (e) {
      error = errorMessage(e, 'Could not resend the email');
    } finally {
      loading = false;
    }
  }

  const TITLES: Record<Mode, string> = {
    login: 'HE SaaS Login',
    register: 'Create an Account',
    forgot: 'Reset your password'
  };
  const SUBMIT: Record<Mode, string> = { login: 'Login', register: 'Register', forgot: 'Send reset link' };
</script>

<svelte:head><title>Sign in · HEaaS</title></svelte:head>

<div class="container">
  <h1>{TITLES[mode]}</h1>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if notice}<p class="notice" role="status">{notice}</p>{/if}
  {#if registeredEmail && mode === 'login'}
    <p class="toggle-text">
      No email?
      <button class="btn-link" type="button" onclick={resend} disabled={loading}>Resend verification email</button>
    </p>
  {/if}
  <form onsubmit={handleSubmit}>
    <label for="email">Email <span class="required" aria-hidden="true">*</span></label>
    <input id="email" type="email" bind:value={email} placeholder="email@example.com" autocomplete="email" required />

    {#if mode !== 'forgot'}
      <label for="password">Password <span class="required" aria-hidden="true">*</span></label>
      <div class="password-wrapper">
        <input
          id="password"
          type={showPassword ? 'text' : 'password'}
          bind:value={password}
          placeholder="••••••••"
          autocomplete={mode === 'login' ? 'current-password' : 'new-password'}
          required
        />
        <button
          type="button"
          class="toggle-password"
          onclick={() => (showPassword = !showPassword)}
          aria-label={showPassword ? 'Hide password' : 'Show password'}
          aria-pressed={showPassword}
        >
          {showPassword ? 'HIDE' : 'SHOW'}
        </button>
      </div>
    {/if}

    {#if passwordHint}
      <ul class="hint" aria-live="polite">
        <li class:ok={password.length >= 10 && password.length <= 128}>Between 10 and 128 characters</li>
        <li class:ok={/\p{Lu}/u.test(password)}>One uppercase letter</li>
        <li class:ok={/\p{Ll}/u.test(password)}>One lowercase letter</li>
        <li class:ok={/[0-9]/.test(password)}>One digit</li>
        <li class:ok={/[^\p{L}\p{N}]/u.test(password)}>One special character</li>
      </ul>
    {/if}

    <button type="submit" disabled={loading || (mode === 'register' && !isStrongPassword(password))} class="btn-primary">
      {loading ? 'Processing...' : SUBMIT[mode]}
    </button>
  </form>

  {#if mode === 'login'}
    <p class="toggle-text">
      <button class="btn-link" type="button" onclick={() => switchTo('forgot')}>Forgot password?</button>
    </p>
    {#if providers.google || providers.github}
      <div class="oauth">
        <!-- Full-page navigations to the API: the server redirects to the provider. -->
        {#if providers.google}<a class="btn-oauth" href="/api/v1/auth/google" rel="external">Continue with Google</a>{/if}
        {#if providers.github}<a class="btn-oauth" href="/api/v1/auth/github" rel="external">Continue with GitHub</a>{/if}
      </div>
    {/if}
  {/if}

  <p class="toggle-text">
    {#if mode === 'register'}
      Already have an account?
      <button class="btn-link" onclick={() => switchTo('login')} type="button">Login</button>
    {:else if mode === 'forgot'}
      Remembered it?
      <button class="btn-link" onclick={() => switchTo('login')} type="button">Back to login</button>
    {:else}
      Don't have an account?
      <button class="btn-link" onclick={() => switchTo('register')} type="button">Register</button>
    {/if}
  </p>
</div>

<style>
  .notice { color: var(--success); margin: 0.5rem 0; }
  .oauth { display: flex; flex-direction: column; gap: 0.5rem; margin-top: 1rem; }
  .btn-oauth {
    display: block; text-align: center; padding: 0.65rem 1rem; border-radius: 8px;
    border: 1px solid var(--border-strong); color: inherit; text-decoration: none;
  }
  .btn-oauth:hover { border-color: var(--accent); }
  .container { max-width: 420px; margin: 3rem auto; padding: 2rem; }
  h1 { margin-bottom: 1.25rem; font-size: 1.375rem; text-align: center; }
  .toggle-text { margin-top: 1.5rem; text-align: center; font-size: 0.875rem; color: var(--text-secondary); }
  .btn-link {
    background: none; border: none; color: var(--link); cursor: pointer;
    text-decoration: underline; padding: 0; font-size: inherit;
  }

  /* ── Hint ── */
  .hint {
    list-style: none; padding: 0.5rem 0.75rem; margin: 0.25rem 0 0.75rem;
    background: var(--bg-secondary); border-radius: 6px; font-size: 0.8rem;
    display: flex; flex-direction: column; gap: 0.2rem;
  }
  .hint li { color: var(--text-secondary); }
  .hint li::before { content: '✗ '; color: var(--error); }
  .hint li.ok { color: var(--success); }
  .hint li.ok::before { content: '✓ '; }
</style>
