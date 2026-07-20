## 2026-06-03 - Token Hashing & Error Sanitization
**Vulnerability:** Plaintext storage of email verification and password reset tokens; information disclosure in JWT error messages.
**Learning:** Storing tokens in plaintext exposes them to database leaks. Detailed error messages can leak authentication internals.
**Prevention:** Hash sensitive tokens before storage. Use generic error messages for the client while logging details internally.

## 2026-06-06 - Hashing-induced Denial of Service (DoS)
**Vulnerability:** Input fields for email and password did not enforce any maximum length limit, allowing attackers to send arbitrarily large payloads (e.g. multi-megabyte passwords) to endpoints that perform CPU-intensive hashing (bcrypt) or DB queries.
**Learning:** CPU-intensive algorithms like bcrypt scale non-linearly with input length (or consume excessive memory/cycles), which can easily block thread pools and crash the service if unbounded strings are hashed.
**Prevention:** Enforce strict maximum length limits at the validation layer before any hashing or DB queries are performed (e.g., maximum email length of 254 characters and maximum password length of 128 characters).
