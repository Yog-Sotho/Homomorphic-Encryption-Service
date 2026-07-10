## 2026-06-03 - Token Hashing & Error Sanitization
**Vulnerability:** Plaintext storage of email verification and password reset tokens; information disclosure in JWT error messages.
**Learning:** Storing tokens in plaintext exposes them to database leaks. Detailed error messages can leak authentication internals.
**Prevention:** Hash sensitive tokens before storage. Use generic error messages for the client while logging details internally.
