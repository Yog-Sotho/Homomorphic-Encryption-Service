## 2026-06-07 - Input Length CPU-Exhaustion DoS on Token Hashing
**Vulnerability:** Unconstrained token lengths (e.g., verification tokens, password reset tokens, refresh tokens) on authentication, refresh, and logout endpoints allowed potential Denial of Service (DoS) attacks via CPU exhaustion by forcing SHA-256 hashing over arbitrarily large request payloads.
**Learning:** Checking the length of user-supplied token parameters early in the request handler prevents downstream CPU-heavy hashing operations and database load.
**Prevention:** Enforce generous but strict length limits (<= 256 characters) on all input tokens before any cryptographic hashing or database lookups are initiated.

## 2026-06-06 - Input Length CPU-Exhaustion DoS on BCrypt and DB
**Vulnerability:** Unconstrained email and password input lengths on authentication, password change, and account deletion endpoints allowed potential Denial of Service (DoS) attacks via CPU exhaustion on expensive cryptographic hashing (bcrypt) or database server resources.
**Learning:** Centralized validation logic must enforce maximum payload limits in addition to format and strength requirements before any downstream CPU-heavy cryptographic operations or complex DB queries are performed.
**Prevention:** Enforce strict length limits (<= 254 characters for email, <= 128 characters for password) early in the handler or validation function and immediately reject invalid requests.

## 2026-06-03 - Login Account Enumeration
**Vulnerability:** The login endpoint leaked account existence and type (password vs social) through specific error messages ("Please verify your email...", "This account was created with social login...").
**Learning:** Returning specific errors before password verification or based on account state allows attackers to enumerate registered emails and identify authentication methods.
**Prevention:** Use generic "Invalid credentials" error messages for all failed login attempts and ensure constant-time-ish behavior by always performing a password hash verification (real or dummy).

## 2026-06-04 - Pre-registration OAuth Account Takeover
**Vulnerability:** Pre-registering an unverified account using a victim's email allows an attacker to set an initial password. When the victim later logs in via Google or GitHub OAuth, the system links the unverified account without clearing the `password_hash` or `email_verify_token`, allowing the attacker to maintain password-based access.
**Learning:** Federated OAuth login must establish the identity as fully verified, which requires invalidating any existing unverified local password/tokens to prevent account hijacking.
**Prevention:** In `find_or_create_oauth_user`, if the existing account is unverified (`email_verified = 0`), set `password_hash = ''` and `email_verify_token = NULL` when linking to ensure the attacker is permanently locked out.
## 2026-06-05 - OAuth Pre-Registration Takeover
**Vulnerability:** Existing unverified accounts could be claimed via OAuth without clearing existing credentials, potentially allowing an attacker who pre-registered an email to retain access or intercept tokens if the legitimate owner later signed in via OAuth.
**Learning:** Linking OAuth providers to existing accounts must be treated as a "claim" event that invalidates previous unverified states or weak credentials.
**Prevention:** When linking an OAuth provider to an existing unverified account, always clear `password_hash` and `email_verify_token` to ensure only the OAuth identity can access the account.
## 2026-06-04 - Account Enumeration and OAuth Takeover
**Vulnerability:** Account enumeration via database unique constraint errors and account takeover of unverified accounts during OAuth linking.
**Learning:** Returning specific "Email already registered" messages from the database layer allows enumeration. OAuth linking to unverified accounts can leave attacker-controlled passwords active.
**Prevention:** Catch unique constraint violations and return generic success or error messages. Clear password hashes and verification tokens when taking over unverified accounts via OAuth.
