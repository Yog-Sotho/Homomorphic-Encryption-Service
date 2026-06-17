## 2025-06-17 - Secure Error Handling Pattern
**Vulnerability:** Information Disclosure
**Learning:** Default error conversions (e.g., `From<sqlx::Error>`) and `ResponseError` implementations were leaking internal system details like SQL query strings, database structure, and JWT library internals directly to the client.
**Prevention:** Use a dedicated `AppError` type that implements `ResponseError`. In `From` trait implementations for external errors, log the detailed error internally using `log::error!` and return a generic, sanitized message (e.g., "Internal server error") to the client. Map generic messages to appropriate HTTP status codes in the `status_code()` method.
