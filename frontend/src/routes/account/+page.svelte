<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { base } from '$app/paths';
  import { user, auth } from '$lib/api';
  import { userStore } from '$lib/stores';

  interface UserProfile {
    id: string;
    email: string;
    created_at: string;
    email_verified: boolean;
    has_password: boolean;
    oauth_providers: string[];
    daily_usage: { count: number; quota: number; date: string };
  }

  let profile: UserProfile | null = null;
  let loadError = '';

  // Change password
  let currentPassword = '';
  let newPassword = '';
  let confirmPassword = '';
  let showCurrentPassword = false;
  let showNewPassword = false;
  let showConfirmPassword = false;
  let passwordLoading = false;
  let passwordError = '';
  let passwordSuccess = false;

  // Delete account
  let showDeleteConfirm = false;
  let deleteConfirmText = '';
  let deletePassword = '';
  let showDeletePassword = false;
  let deleteLoading = false;
  let deleteError = '';

  $: passwordHint = newPassword.length > 0 && !isValidPassword(newPassword);
  $: passwordMismatch = newPassword.length > 0 && confirmPassword.length > 0 && newPassword !== confirmPassword;
  $: usagePercent = profile ? Math.min(100, Math.round((profile.daily_usage.count / Math.max(profile.daily_usage.quota, 1)) * 100)) : 0;
  $: memberSince = profile ? formatDate(profile.created_at) : '';

  function isValidPassword(p: string): boolean {
    return p.length >= 8 && /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p);
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
    } catch { return iso; }
  }

  onMount(async () => {
    try {
      const res = await user.me();
      profile = res.data;
      if (profile && $userStore) {
        userStore.set({ ...$userStore, email: profile.email });
      }
    } catch (e: any) {
      if (e.response?.status === 401) {
        goto(`${base}/login`);
      } else {
        loadError = 'Failed to load account data.';
      }
    }
  });

  async function handleChangePassword() {
    passwordLoading = true; passwordError = ''; passwordSuccess = false;
    try {
      await user.changePassword(currentPassword, newPassword);
      passwordSuccess = true;
      currentPassword = ''; newPassword = ''; confirmPassword = '';
    } catch (e: any) {
      passwordError = e.response?.data?.message || 'Failed to change password.';
    } finally { passwordLoading = false; }
  }

  async function handleDeleteAccount() {
    if (deleteConfirmText !== 'DELETE') return;
    deleteLoading = true; deleteError = '';
    try {
      await user.deleteAccount(deletePassword);
      localStorage.removeItem('token');
      localStorage.removeItem('refresh_token');
      userStore.set(null);
      goto(`${base}/login`);
    } catch (e: any) {
      deleteError = e.response?.data?.message || 'Failed to delete account.';
      deleteLoading = false;
    }
  }
</script>

<svelte:head>
  <title>Account - HEaaS</title>
</svelte:head>

<div class="page">
  <div class="page-header">
    <h1>Account</h1>
    <p class="page-subtitle">Manage your profile and account settings</p>
  </div>

  {#if loadError}
    <div class="card">
      <p class="err-text">{loadError}</p>
    </div>
  {:else if !profile}
    <div class="card loading-card">
      <span class="spinner"></span>
      <span class="loading-text">Loading…</span>
    </div>
  {:else}
    <!-- Profile section -->
    <div class="card">
      <div class="section-header">
        <span class="section-label">Profile</span>
      </div>
      <div class="profile-grid">
        <div class="profile-row">
          <span class="field-label">Email</span>
          <span class="field-value mono">{profile.email}</span>
          {#if profile.email_verified}
            <span class="badge badge-green">Verified</span>
          {:else}
            <span class="badge badge-red">Unverified</span>
          {/if}
        </div>
        <div class="profile-row">
          <span class="field-label">Member since</span>
          <span class="field-value">{memberSince}</span>
        </div>
        <div class="profile-row">
          <span class="field-label">Account ID</span>
          <span class="field-value mono muted">{profile.id}</span>
        </div>
      </div>
    </div>

    <!-- Daily usage section -->
    <div class="card">
      <div class="section-header">
        <span class="section-label">Daily Usage</span>
        <span class="usage-count mono">{profile.daily_usage.count} / {profile.daily_usage.quota}</span>
      </div>
      <p class="section-desc">Homomorphic compute operations used today</p>
      <div class="progress-track" role="progressbar" aria-valuenow={profile.daily_usage.count} aria-valuemin={0} aria-valuemax={profile.daily_usage.quota}>
        <div class="progress-fill" style="width: {usagePercent}%" class:progress-warn={usagePercent >= 80} class:progress-full={usagePercent >= 100}></div>
      </div>
      <p class="progress-label">{usagePercent}% of daily quota used</p>
    </div>

    <!-- Linked accounts section -->
    {#if profile.oauth_providers && profile.oauth_providers.length > 0}
      <div class="card">
        <div class="section-header">
          <span class="section-label">Linked Accounts</span>
        </div>
        <div class="providers-list">
          {#each profile.oauth_providers as provider}
            <div class="provider-item">
              {#if provider === 'google'}
                <svg width="16" height="16" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
                  <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.874 2.684-6.615z" fill="#4285F4"/>
                  <path d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.258c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z" fill="#34A853"/>
                  <path d="M3.964 10.707A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.707V4.961H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.039l3.007-2.332z" fill="#FBBC05"/>
                  <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.961L3.964 7.293C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335"/>
                </svg>
              {:else if provider === 'github'}
                <svg width="16" height="16" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true" fill="currentColor">
                  <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
                </svg>
              {/if}
              <span class="provider-name">{provider.charAt(0).toUpperCase() + provider.slice(1)}</span>
              <span class="badge badge-indigo">Connected</span>
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <!-- Change password section -->
    <div class="card">
      <div class="section-header">
        <span class="section-label">Change Password</span>
      </div>
      <form on:submit|preventDefault={handleChangePassword} class="settings-form">
        <label for="current-password">Current Password</label>
        <div class="password-wrapper">
          <input id="current-password" type={showCurrentPassword ? 'text' : 'password'} bind:value={currentPassword} placeholder="••••••••" required autocomplete="current-password" />
          <button type="button" class="toggle-password" on:click={() => showCurrentPassword = !showCurrentPassword} aria-label={showCurrentPassword ? 'Hide current password' : 'Show current password'} aria-pressed={showCurrentPassword}>
            {showCurrentPassword ? 'HIDE' : 'SHOW'}
          </button>
        </div>

        <label for="new-password">New Password</label>
        <div class="password-wrapper">
          <input id="new-password" type={showNewPassword ? 'text' : 'password'} bind:value={newPassword} placeholder="••••••••" required autocomplete="new-password" />
          <button type="button" class="toggle-password" on:click={() => showNewPassword = !showNewPassword} aria-label={showNewPassword ? 'Hide new password' : 'Show new password'} aria-pressed={showNewPassword}>
            {showNewPassword ? 'HIDE' : 'SHOW'}
          </button>
        </div>

        {#if passwordHint}
          <ul class="hint" aria-live="polite">
            <li class:ok={newPassword.length >= 8}>At least 8 characters</li>
            <li class:ok={/[A-Z]/.test(newPassword)}>One uppercase letter</li>
            <li class:ok={/[a-z]/.test(newPassword)}>One lowercase letter</li>
            <li class:ok={/[0-9]/.test(newPassword)}>One digit</li>
          </ul>
        {/if}

        <label for="confirm-password">Confirm New Password</label>
        <div class="password-wrapper">
          <input id="confirm-password" type={showConfirmPassword ? 'text' : 'password'} bind:value={confirmPassword} placeholder="••••••••" required autocomplete="new-password" />
          <button type="button" class="toggle-password" on:click={() => showConfirmPassword = !showConfirmPassword} aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'} aria-pressed={showConfirmPassword}>
            {showConfirmPassword ? 'HIDE' : 'SHOW'}
          </button>
        </div>

        {#if passwordMismatch}
          <p class="field-error">Passwords do not match.</p>
        {/if}

        {#if passwordError}
          <p class="field-error" role="alert">{passwordError}</p>
        {/if}
        {#if passwordSuccess}
          <p class="field-success">Password updated successfully.</p>
        {/if}

        <div class="form-actions">
          <button type="submit" class="btn-primary btn-inline"
            disabled={passwordLoading || !currentPassword || !isValidPassword(newPassword) || newPassword !== confirmPassword}>
            {passwordLoading ? 'Saving…' : 'Update Password'}
          </button>
        </div>
      </form>
    </div>

    <!-- Danger zone -->
    <div class="card danger-card">
      <div class="section-header">
        <span class="section-label danger-label">Danger Zone</span>
      </div>

      {#if !showDeleteConfirm}
        <div class="danger-row">
          <div>
            <p class="danger-title">Delete account</p>
            <p class="danger-desc">Permanently delete your account and all associated data. This action cannot be undone.</p>
          </div>
          <button type="button" class="btn-danger" on:click={() => showDeleteConfirm = true}>
            Delete account
          </button>
        </div>
      {:else}
        <div class="delete-confirm">
          <p class="danger-desc">This will permanently delete your account. To confirm, type <strong>DELETE</strong> in the box below.</p>

          <label for="delete-confirm-input">Type DELETE to confirm</label>
          <input id="delete-confirm-input" type="text" bind:value={deleteConfirmText} placeholder="DELETE" autocomplete="off" />

          {#if profile.has_password}
            <label for="delete-password">Your password</label>
            <div class="password-wrapper">
              <input id="delete-password" type={showDeletePassword ? 'text' : 'password'} bind:value={deletePassword} placeholder="••••••••" autocomplete="current-password" />
              <button type="button" class="toggle-password" on:click={() => showDeletePassword = !showDeletePassword} aria-label={showDeletePassword ? 'Hide delete password' : 'Show delete password'} aria-pressed={showDeletePassword}>
                {showDeletePassword ? 'HIDE' : 'SHOW'}
              </button>
            </div>
          {/if}

          {#if deleteError}
            <p class="field-error" role="alert">{deleteError}</p>
          {/if}

          <div class="delete-actions">
            <button type="button" class="btn-secondary" on:click={() => { showDeleteConfirm = false; deleteConfirmText = ''; deletePassword = ''; deleteError = ''; }}>
              Cancel
            </button>
            <button type="button" class="btn-danger"
              disabled={deleteLoading || deleteConfirmText !== 'DELETE'}
              on:click={handleDeleteAccount}>
              {deleteLoading ? 'Deleting…' : 'Confirm delete'}
            </button>
          </div>
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .page { display: flex; flex-direction: column; gap: 1rem; }

  .page-header { margin-bottom: 0.25rem; }
  .page-subtitle { font-size: 0.875rem; color: var(--text-secondary); margin-top: 0.25rem; }

  /* ── Section headers ── */
  .section-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 1rem;
  }
  .section-label {
    font-size: 0.6875rem; font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.08em; text-transform: uppercase;
  }
  .section-desc { font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.75rem; }

  /* ── Loading ── */
  .loading-card { display: flex; align-items: center; gap: 0.75rem; }
  .loading-text { font-size: 0.875rem; color: var(--text-secondary); }

  /* ── Profile grid ── */
  .profile-grid { display: flex; flex-direction: column; gap: 0.875rem; }
  .profile-row { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
  .field-label {
    font-size: 0.75rem; font-weight: 600;
    color: var(--text-muted);
    min-width: 110px;
    letter-spacing: 0.04em;
  }
  .field-value { font-size: 0.9rem; color: var(--text-primary); }
  .mono { font-family: var(--font-mono); font-size: 0.8375rem; }
  .muted { color: var(--text-secondary); }

  /* ── Usage bar ── */
  .usage-count { font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-secondary); }
  .progress-track {
    height: 6px; background: var(--bg-secondary);
    border-radius: 999px; overflow: hidden;
    border: 1px solid var(--border);
  }
  .progress-fill {
    height: 100%; background: var(--accent);
    border-radius: 999px;
    transition: width 0.4s ease;
  }
  .progress-fill.progress-warn { background: var(--warning); }
  .progress-fill.progress-full { background: var(--error); }
  .progress-label { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.375rem; }

  /* ── Providers ── */
  .providers-list { display: flex; flex-direction: column; gap: 0.625rem; }
  .provider-item {
    display: flex; align-items: center; gap: 0.625rem;
    padding: 0.5rem 0.75rem;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
  }
  .provider-name { font-size: 0.875rem; color: var(--text-primary); flex: 1; }

  /* ── Settings form ── */
  .settings-form { display: flex; flex-direction: column; }
  .form-actions { display: flex; justify-content: flex-start; margin-top: 0.25rem; }
  .btn-inline { width: auto; padding: 0.5rem 1.25rem; font-size: 0.875rem; }

  /* ── Hint ── */
  .hint {
    list-style: none; padding: 0.5rem 0.75rem; margin: 0.25rem 0 0.75rem;
    background: var(--bg-secondary); border-radius: 6px; font-size: 0.8rem;
    display: flex; flex-direction: column; gap: 0.2rem;
  }
  .hint li { color: var(--text-secondary); }
  .hint li::before { content: '✗ '; color: #ef4444; }
  .hint li.ok { color: #22c55e; }
  .hint li.ok::before { content: '✓ '; }

  /* ── Messages ── */
  .field-error { font-size: 0.8rem; color: var(--error); margin-bottom: 0.75rem; }
  .field-success { font-size: 0.8rem; color: var(--success); margin-bottom: 0.75rem; }
  .err-text { color: var(--error); font-size: 0.9rem; }

  /* ── Danger zone ── */
  .danger-card { border-color: rgba(239, 68, 68, 0.2); }
  .danger-label { color: var(--error); }
  .danger-row {
    display: flex; align-items: flex-start; justify-content: space-between;
    gap: 1rem; flex-wrap: wrap;
  }
  .danger-title { font-size: 0.9rem; font-weight: 600; color: var(--text-primary); margin-bottom: 0.25rem; }
  .danger-desc { font-size: 0.8rem; color: var(--text-secondary); line-height: 1.5; }
  .danger-desc strong { color: var(--text-primary); }

  .btn-danger {
    display: inline-flex; align-items: center; justify-content: center;
    padding: 0.5rem 1rem;
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: var(--radius-sm);
    color: #fca5a5;
    font-size: 0.875rem; font-weight: 500;
    transition: background 0.15s, border-color 0.15s;
    white-space: nowrap;
  }
  .btn-danger:hover:not(:disabled) {
    background: rgba(239, 68, 68, 0.2);
    border-color: rgba(239, 68, 68, 0.5);
    color: #f87171;
  }
  .btn-danger:disabled { opacity: 0.4; cursor: not-allowed; }

  .delete-confirm { display: flex; flex-direction: column; gap: 0.25rem; }
  .delete-actions { display: flex; gap: 0.625rem; margin-top: 0.5rem; }

  @media (max-width: 600px) {
    .profile-row { flex-direction: column; align-items: flex-start; gap: 0.25rem; }
    .field-label { min-width: unset; }
    .danger-row { flex-direction: column; }
  }
</style>
