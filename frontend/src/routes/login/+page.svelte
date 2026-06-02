<script lang="ts">
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import { onMount } from 'svelte';
  import { auth } from '$lib/api';
  import { userStore } from '$lib/stores';

  let email = '', password = '', error = '', loading = false, isLogin = true;
  let pageMode: 'auth' | 'verify-pending' | 'forgot' | 'reset-pending' | 'reset-form' = 'auth';
  let stateEmail = '';
  let resetToken = '';
  let resendLoading = false, resendMessage = '';

  // Forgot password state
  let forgotEmail = '';
  let forgotLoading = false;
  let forgotMessage = '';

  // Reset password state
  let newPassword = '';
  let confirmPassword = '';
  let resetLoading = false;
  let resetError = '';
  let resetSuccess = false;

  $: passwordHint = !isLogin && password.length > 0 && !isValidPassword(password);
  $: resetPasswordHint = newPassword.length > 0 && !isValidPassword(newPassword);
  $: resetPasswordsMatch = newPassword.length > 0 && confirmPassword.length > 0 && newPassword !== confirmPassword;

  function isValidPassword(p: string): boolean {
    return p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p);
  }

  onMount(() => {
    const hash = window.location.hash.slice(1);
    if (!hash) return;
    const params = new URLSearchParams(hash);
    const token = params.get('token');
    const userEmail = params.get('email');
    const oauthError = params.get('error');
    const resetTok = params.get('reset_token');
    history.replaceState(null, '', window.location.pathname + window.location.search);
    if (resetTok) {
      resetToken = resetTok;
      pageMode = 'reset-form';
    } else if (token && userEmail) {
      const refreshToken = params.get('refresh_token');
      localStorage.setItem('token', token);
      if (refreshToken) localStorage.setItem('refresh_token', refreshToken);
      userStore.set({ email: userEmail });
      goto(`${base}/dashboard`);
    } else if (oauthError) {
      error = decodeURIComponent(oauthError).replace(/\+/g, ' ');
    }
  });

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
        stateEmail = email;
        pageMode = 'verify-pending';
      }
    } catch (e: any) {
      const status = e.response?.status;
      const msg = e.response?.data?.message ?? '';
      if (status === 403 && msg.toLowerCase().includes('verify')) {
        stateEmail = email;
        pageMode = 'verify-pending';
      } else {
        error = msg || (isLogin ? 'Login failed' : 'Registration failed');
      }
    } finally { loading = false; }
  }

  async function resend() {
    resendLoading = true; resendMessage = '';
    try {
      await auth.resendVerification(stateEmail);
      resendMessage = 'New link sent — check your inbox.';
    } catch {
      resendMessage = 'Failed to resend. Try again shortly.';
    } finally { resendLoading = false; }
  }

  async function handleForgot() {
    forgotLoading = true; forgotMessage = '';
    try {
      await auth.forgotPassword(forgotEmail);
      pageMode = 'reset-pending';
    } catch {
      forgotMessage = 'Failed to send reset email. Try again.';
    } finally { forgotLoading = false; }
  }

  async function handleReset() {
    resetLoading = true; resetError = '';
    try {
      await auth.resetPassword(resetToken, newPassword);
      resetSuccess = true;
    } catch (e: any) {
      resetError = e.response?.data?.message || 'Reset failed.';
    } finally { resetLoading = false; }
  }

  function oauthRedirect(provider: 'google' | 'github') {
    window.location.href = '/api/auth/' + provider;
  }
</script>

<div class="container">
  <img src="{base}/logo.svg" alt="HEaaS" class="page-logo" />

  {#if pageMode === 'verify-pending'}
    <div class="verify-pending">
      <svg class="envelope-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <rect x="2" y="4" width="20" height="16" rx="2"/>
        <path d="m2 7 10 7 10-7"/>
      </svg>
      <h2>Check your inbox</h2>
      <p>We sent a verification link to<br><strong>{stateEmail}</strong></p>
      <p class="verify-hint">Click the link in the email to activate your account and sign in.</p>
      <button class="btn-primary resend-btn" on:click={resend} disabled={resendLoading} type="button">
        {resendLoading ? 'Sending…' : 'Resend link'}
      </button>
      {#if resendMessage}
        <p class="resend-msg" class:resend-ok={resendMessage.includes('sent')}>{resendMessage}</p>
      {/if}
      <button class="btn-link back-btn" on:click={() => { pageMode = 'auth'; resendMessage = ''; error = ''; }} type="button">
        &larr; Back to sign in
      </button>
    </div>

  {:else if pageMode === 'forgot'}
    <div class="state-section">
      <h1>Reset Password</h1>
      <p class="state-desc">Enter your email address and we will send you a password reset link.</p>
      <form on:submit|preventDefault={handleForgot}>
        <label for="forgot-email">Email</label>
        <input id="forgot-email" type="email" bind:value={forgotEmail} placeholder="you@example.com" required autocomplete="email" />
        {#if forgotMessage}
          <p class="form-error" role="alert">{forgotMessage}</p>
        {/if}
        <button type="submit" class="btn-primary" disabled={forgotLoading}>
          {forgotLoading ? 'Sending…' : 'Send reset link'}
        </button>
      </form>
      <p class="toggle-text">
        <button class="btn-link" on:click={() => { pageMode = 'auth'; forgotMessage = ''; }} type="button">
          &larr; Back to sign in
        </button>
      </p>
    </div>

  {:else if pageMode === 'reset-pending'}
    <div class="verify-pending">
      <svg class="envelope-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <rect x="2" y="4" width="20" height="16" rx="2"/>
        <path d="m2 7 10 7 10-7"/>
      </svg>
      <h2>Check your inbox</h2>
      <p>We sent a password reset link to your email address.</p>
      <p class="verify-hint">Click the link in the email to set a new password.</p>
      <button class="btn-link back-btn" on:click={() => { pageMode = 'auth'; }} type="button">
        &larr; Back to sign in
      </button>
    </div>

  {:else if pageMode === 'reset-form'}
    <div class="state-section">
      {#if resetSuccess}
        <div class="verify-pending">
          <svg class="success-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
          <h2>Password reset successfully</h2>
          <p class="verify-hint">You can now sign in with your new password.</p>
          <button class="btn-primary" on:click={() => { pageMode = 'auth'; resetSuccess = false; newPassword = ''; confirmPassword = ''; }} type="button">
            Sign in
          </button>
        </div>
      {:else}
        <h1>Set new password</h1>
        <p class="state-desc">Choose a strong password for your account.</p>
        <form on:submit|preventDefault={handleReset}>
          <label for="new-password">New Password</label>
          <input id="new-password" type="password" bind:value={newPassword} placeholder="••••••••" required autocomplete="new-password" />
          {#if resetPasswordHint}
            <ul class="hint" aria-live="polite">
              <li class:ok={newPassword.length >= 8}>At least 8 characters</li>
              <li class:ok={/[A-Z]/.test(newPassword)}>One uppercase letter</li>
              <li class:ok={/[a-z]/.test(newPassword)}>One lowercase letter</li>
              <li class:ok={/[0-9]/.test(newPassword)}>One digit</li>
            </ul>
          {/if}
          <label for="confirm-password">Confirm Password</label>
          <input id="confirm-password" type="password" bind:value={confirmPassword} placeholder="••••••••" required autocomplete="new-password" />
          {#if resetPasswordsMatch}
            <p class="form-error">Passwords do not match.</p>
          {/if}
          {#if resetError}
            <p class="form-error" role="alert">{resetError}</p>
          {/if}
          <button type="submit" class="btn-primary" disabled={resetLoading || !isValidPassword(newPassword) || newPassword !== confirmPassword}>
            {resetLoading ? 'Resetting…' : 'Reset Password'}
          </button>
        </form>
      {/if}
    </div>

  {:else}
    <h1>{isLogin ? 'Sign In' : 'Create Account'}</h1>
    {#if error}<p class="error" role="alert">{error}</p>{/if}

    <div class="oauth-row">
      <button type="button" class="btn-oauth btn-google" on:click={() => oauthRedirect('google')}>
        <svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z" fill="#4285F4"/>
          <path d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.258c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z" fill="#34A853"/>
          <path d="M3.964 10.707A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.707V4.961H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.039l3.007-2.332z" fill="#FBBC05"/>
          <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.961L3.964 7.293C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335"/>
        </svg>
        Continue with Google
      </button>
      <button type="button" class="btn-oauth btn-github" on:click={() => oauthRedirect('github')}>
        <svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" fill="currentColor">
          <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
        </svg>
        Continue with GitHub
      </button>
    </div>

    <div class="divider"><span>or</span></div>

    <form on:submit|preventDefault={handleSubmit}>
      <label for="email">Email</label>
      <input id="email" type="email" bind:value={email} placeholder="you@example.com" required autocomplete="email" />

      <label for="password">Password</label>
      <input id="password" type="password" bind:value={password} placeholder="••••••••" required
        autocomplete={isLogin ? 'current-password' : 'new-password'} />

      {#if isLogin}
        <div class="forgot-row">
          <button class="btn-link forgot-link" type="button" on:click={() => { pageMode = 'forgot'; forgotEmail = email; }}>
            Forgot password?
          </button>
        </div>
      {/if}

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
  {/if}
</div>

<style>
  .container { max-width: 420px; margin: 3rem auto; padding: 2rem; }
  .page-logo { width: 200px; height: auto; display: block; margin: 0 auto 1.75rem; }
  h1 { margin-bottom: 1.25rem; font-size: 1.375rem; text-align: center; }
  .toggle-text { margin-top: 1.5rem; text-align: center; font-size: 0.875rem; color: var(--text-secondary); }
  .btn-link { background: none; border: none; color: var(--accent); cursor: pointer; text-decoration: underline; padding: 0; font-size: inherit; }

  /* ── State sections ── */
  .state-section { display: flex; flex-direction: column; }
  .state-desc { font-size: 0.875rem; color: var(--text-secondary); margin-bottom: 1.5rem; text-align: center; }

  /* ── Forgot password link ── */
  .forgot-row { display: flex; justify-content: flex-end; margin-top: -0.75rem; margin-bottom: 0.75rem; }
  .forgot-link { font-size: 0.8rem; }

  /* ── Form error ── */
  .form-error { font-size: 0.8rem; color: var(--error); margin-bottom: 0.75rem; }
  .error { font-size: 0.875rem; color: var(--error); margin-bottom: 1rem; text-align: center; }

  /* ── Verification pending ── */
  .verify-pending {
    display: flex; flex-direction: column; align-items: center;
    text-align: center; gap: 0.75rem; padding: 1rem 0;
  }
  .envelope-icon {
    width: 48px; height: 48px; color: var(--accent);
    margin-bottom: 0.5rem;
  }
  .success-icon {
    width: 48px; height: 48px; color: var(--success);
    margin-bottom: 0.5rem;
  }
  .verify-pending h2 { font-size: 1.25rem; }
  .verify-pending p { color: var(--text-secondary); font-size: 0.9rem; line-height: 1.5; }
  .verify-pending strong { color: var(--text-primary); }
  .verify-hint { font-size: 0.8rem !important; color: var(--text-muted) !important; }
  .resend-btn { margin-top: 0.5rem; }
  .resend-msg { font-size: 0.8rem; color: var(--text-muted); }
  .resend-msg.resend-ok { color: var(--success); }
  .back-btn { margin-top: 0.5rem; font-size: 0.85rem; }

  /* ── Password hint ── */
  .hint {
    list-style: none; padding: 0.5rem 0.75rem; margin: 0.25rem 0 0.75rem;
    background: var(--bg-secondary); border-radius: 6px; font-size: 0.8rem;
    display: flex; flex-direction: column; gap: 0.2rem;
  }
  .hint li { color: var(--text-secondary); }
  .hint li::before { content: '✗ '; color: #ef4444; }
  .hint li.ok { color: #22c55e; }
  .hint li.ok::before { content: '✓ '; }

  /* ── OAuth ── */
  .oauth-row { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1rem; }
  .btn-oauth {
    display: flex; align-items: center; justify-content: center; gap: 0.6rem;
    width: 100%; padding: 0.65rem 1rem; border-radius: 8px;
    font-size: 0.9rem; font-weight: 500; cursor: pointer;
    transition: opacity 0.15s, box-shadow 0.15s;
    border: 1px solid var(--border, rgba(255,255,255,0.12));
  }
  .btn-oauth:hover { opacity: 0.88; box-shadow: 0 2px 8px rgba(0,0,0,0.25); }
  .btn-google { background: #fff; color: #3c4043; border-color: #dadce0; }
  .btn-github { background: #24292e; color: #fff; border-color: #444d56; }

  .divider {
    display: flex; align-items: center; gap: 0.75rem;
    margin: 1.25rem 0; color: var(--text-secondary); font-size: 0.8rem;
  }
  .divider::before, .divider::after {
    content: ''; flex: 1; height: 1px;
    background: var(--border, rgba(255,255,255,0.12));
  }
</style>
