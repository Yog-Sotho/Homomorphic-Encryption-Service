## 2026-06-03 - Login Account Enumeration
**Vulnerability:** The login endpoint leaked account existence and type (password vs social) through specific error messages ("Please verify your email...", "This account was created with social login...").
**Learning:** Returning specific errors before password verification or based on account state allows attackers to enumerate registered emails and identify authentication methods.
**Prevention:** Use generic "Invalid credentials" error messages for all failed login attempts and ensure constant-time-ish behavior by always performing a password hash verification (real or dummy).

## 2026-06-04 - Registration Account Enumeration
**Vulnerability:** The registration endpoint leaked account existence by returning a 400 error when an email was already registered.
**Learning:** Returning specific errors for duplicate emails allows attackers to scrape the database for registered users. Global error handlers that map database unique constraints to specific messages exacerbate this.
**Prevention:** Return a 202 Accepted status for all valid registration requests, regardless of whether the email exists. Catch and swallow unique constraint violations during user insertion in the registration handler. Ensure global error handlers return generic messages for database constraints.
