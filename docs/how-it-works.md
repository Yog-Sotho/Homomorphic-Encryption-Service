# How HEaaS works

This page explains what happens to your data, which keys exist and where they
live, and what the server can and cannot learn. For a hands-on walkthrough see the
[user guide](user-guide.md); for the exact cryptographic parameters see
[`parameters.md`](parameters.md).

![The three steps: encrypt on your device, compute on the server, decrypt on your device](images/how-it-works.svg)

```
 Your device                                      HEaaS server
 ───────────                                      ────────────
 1. generate key pair  ──────────────────────────▶ (nothing)
    client key (secret) stays here
 2. upload compressed server key  ──────────────▶ stores it; can compute,
                                                   cannot decrypt
 3. encrypt inputs, submit job  ────────────────▶ evaluates op(a, b) on
                                                   ciphertexts with your key
 4. fetch encrypted result  ◀───────────────────── queued job runs on a
                                                   worker; returns a ciphertext
 5. decrypt locally
```

## Architecture

![HEaaS architecture](images/architecture.svg)

`heaas-core` holds what the backend, the SDK and the CLI must agree on: the TFHE
parameters, the operations and the API types.

- **Client key** (~31 KB): generated on your device, used to encrypt and decrypt.
  It is never uploaded. In the dashboard it stays in the browser's IndexedDB,
  encrypted with your passphrase (see [Your key in the browser](#your-key-in-the-browser)).
- **Compressed server key** (~60 MB): an evaluation key derived from the client key.
  It lets the server compute on your ciphertexts but not decrypt them. You register
  it once with `POST /api/v1/keys`; the server checks it against its parameters.
- **Ciphertexts** (~132 KB each): `FheUint16` values. Arithmetic wraps modulo 2¹⁶.

## Parameters

| | |
|---|---|
| Scheme | TFHE (CGGI), TFHE-rs **1.8.2** (pinned; clients must use the same release) |
| Configuration | `ConfigBuilder::default()`: TFHE-rs default parameters (`PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`, failure probability ≤ 2⁻¹²⁸) |
| Integer type | `FheUint16` (0–65535) |
| Operations | `add`, `subtract`, `multiply` (mod 65536), `min`, `max` |
| Live values | `GET /api/v1/he/params` |
| Full parameter sheet | [`parameters.md`](parameters.md), generated from `core/src/params.rs` |

Uploaded keys and ciphertexts are deserialized with TFHE-rs's size-limited,
conformance-checked `safe_deserialize_conformant`, so keys made with other
parameters and malformed or foreign ciphertexts are rejected, not computed on.

## What the server can and cannot learn

The server **cannot** decrypt inputs or results: it only ever holds evaluation keys.

It **does** see metadata: your account, when you submit jobs, which operation each
job uses, ciphertext sizes and how many jobs you run.

Know these limits too:

- **Results are not verifiable.** A dishonest or compromised server could return a
  wrong ciphertext. TFHE alone does not prove that a computation was done correctly.
- **The dashboard trusts its own JavaScript.** The browser code that generates and
  stores your key is served by the operator. If you don't want to trust that code,
  use your own client, such as the [Rust SDK and `heaas` CLI](api.md#rust-sdk-and-heaas-cli).
- **Your passphrase cannot be recovered.** Nobody, including the operator, can reset
  it. Without it (or without a backup file after clearing site data) the key and
  everything encrypted under it is lost.

## Your key in the browser

- **Generated and used in a Web Worker.** Key generation, encryption and decryption run
  in the TFHE worker; the page itself never holds the plaintext client key.
- **Stored sealed.** The worker encrypts the client key with AES-256-GCM under a key
  derived from your passphrase with PBKDF2-HMAC-SHA256 (600,000 iterations, the
  [OWASP recommendation](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html);
  WebCrypto offers no memory-hard KDF). The SHA-256 of the matching evaluation key is
  authenticated alongside, so a sealed key only opens for its own server key.
- **Unlocked per tab.** After a reload, the key must be unlocked with the passphrase
  again. Signing out stops the worker and forgets the unlocked key.
- **Backups.** *Export backup* on the Keys page downloads the sealed key as a JSON
  file (`heaas-key-….json`); it is useless without the passphrase. *Import backup*
  restores it in another browser after checking the passphrase and that the file
  matches one of your registered evaluation keys.
- Keys stored by earlier versions without a passphrase are sealed the first time they
  are unlocked.

---

## Accounts and sessions

- **Sessions.** Signing in returns a 15-minute access token and sets a refresh token
  as an `HttpOnly; Secure; SameSite=Strict` cookie scoped to `/api/v1/auth`. The
  dashboard keeps the access token in memory only, so page scripts can never read
  a long-lived credential. Every refresh rotates the cookie; replaying an old one
  (more than 10 seconds after it was rotated) revokes that whole session.
- **Cross-site requests.** Cookie-authenticated endpoints also refuse requests whose
  `Origin` is not the app's own (`APP_BASE_URL` or `ALLOWED_ORIGINS`).
- **Email links** (verification, password reset) open frontend pages that carry the
  token in the URL fragment and submit it with a POST. Opening a link (or a mail
  scanner prefetching it) changes nothing. Links work once; verification links
  expire after 24 hours and reset links after 1 hour. Tokens are stored hashed.
- **Google and GitHub sign-in** use the authorization-code flow with PKCE and a
  signed state cookie. Only provider-verified email addresses are accepted (GitHub:
  the verified primary address). The callback hands the browser a one-time code,
  never a token, which the page exchanges with `POST /api/v1/auth/exchange`.
- **Rate limits** are keyed on the client IP (the rightmost `X-Forwarded-For` hop not
  added by a `TRUSTED_PROXIES` address, so clients cannot choose their own) and on
  the target email address for sign-in attempts and outgoing email.
- **Sensitive changes.** Changing or resetting the password signs out every session.
  Deleting an account needs its password, or, for Google/GitHub-only accounts, a
  sign-in within the last 5 minutes.
