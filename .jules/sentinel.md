## 2026-06-03 - Login Account Enumeration
**Vulnerability:** The login endpoint leaked account existence and type (password vs social) through specific error messages ("Please verify your email...", "This account was created with social login...").
**Learning:** Returning specific errors before password verification or based on account state allows attackers to enumerate registered emails and identify authentication methods.
**Prevention:** Use generic "Invalid credentials" error messages for all failed login attempts and ensure constant-time-ish behavior by always performing a password hash verification (real or dummy).

## 2026-06-04 - Account Enumeration and OAuth Takeover
**Vulnerability:** Account enumeration via database unique constraint errors and account takeover of unverified accounts during OAuth linking.
**Learning:** Returning specific "Email already registered" messages from the database layer allows enumeration. OAuth linking to unverified accounts can leave attacker-controlled passwords active.
**Prevention:** Catch unique constraint violations and return generic success or error messages. Clear password hashes and verification tokens when taking over unverified accounts via OAuth.
