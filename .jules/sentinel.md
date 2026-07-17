## 2026-06-03 - Login Account Enumeration
**Vulnerability:** The login endpoint leaked account existence and type (password vs social) through specific error messages ("Please verify your email...", "This account was created with social login...").
**Learning:** Returning specific errors before password verification or based on account state allows attackers to enumerate registered emails and identify authentication methods.
**Prevention:** Use generic "Invalid credentials" error messages for all failed login attempts and ensure constant-time-ish behavior by always performing a password hash verification (real or dummy).

## 2026-06-04 - Pre-registration OAuth Account Takeover
**Vulnerability:** Pre-registering an unverified account using a victim's email allows an attacker to set an initial password. When the victim later logs in via Google or GitHub OAuth, the system links the unverified account without clearing the `password_hash` or `email_verify_token`, allowing the attacker to maintain password-based access.
**Learning:** Federated OAuth login must establish the identity as fully verified, which requires invalidating any existing unverified local password/tokens to prevent account hijacking.
**Prevention:** In `find_or_create_oauth_user`, if the existing account is unverified (`email_verified = 0`), set `password_hash = ''` and `email_verify_token = NULL` when linking to ensure the attacker is permanently locked out.
