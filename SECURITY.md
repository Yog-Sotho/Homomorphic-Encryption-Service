# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on the repository's
**Security** tab, choose **Report a vulnerability**. (The repository owner must
have private vulnerability reporting enabled under Settings → Code security.)
Do not open a public issue.

Include what you found, how to reproduce it, and what an attacker gains. The
maintainer aims to acknowledge a report within a week, agrees a disclosure date
with you, and publishes a GitHub security advisory with the fix. You get credit in
the advisory and the changelog if you want it.

## Supported versions

The project is pre-1.0: only the latest release gets security fixes.

| Version | Supported |
|---|---|
| Latest release (0.5.x) | Yes |
| Earlier releases | No: upgrade |

## Verifying a release

Release binaries are signed keylessly with [Sigstore](https://www.sigstore.dev/) by
the release workflow, and container images are signed with cosign and carry build
provenance. [Each release's notes](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/releases) say how to verify them.

## What the HE Engine protects, and what it does not

The HE Engine computes on TFHE ciphertexts (TFHE-rs, see [`docs/parameters.md`](docs/parameters.md)).
In brief:

- **Inputs and results are confidential from the server.** It only ever holds
  users' compressed server (evaluation) keys, compact public keys and
  ciphertexts, never a client (secret) key. A full compromise of the server, its
  database or its backups does not reveal plaintexts.
- **Metadata, and what users choose to send in the clear, is not hidden.** The
  server sees accounts, when jobs run, which operation and type each job uses,
  input counts, ciphertext sizes and job counts, and every plain operand
  (`scalar`) a user sends unencrypted.
- **Proven inputs show that inputs are well formed, not that results are right.**
  The server checks zero-knowledge proofs against a CRS it generates itself; it is
  trusted not to keep a trapdoor for that CRS.
- **Results are not verifiable.** A malicious or compromised server can return a
  wrong ciphertext. TFHE does not prove correct evaluation.
- **The dashboard trusts the code it is served.** In the browser, keys are
  generated and sealed by JavaScript and WebAssembly delivered by the operator. A
  malicious operator could serve code that exfiltrates keys. Users who do not
  trust the operator should use the Rust SDK or CLI, which never send a secret key.
- **Client keys at rest.** In the browser they are sealed with AES-256-GCM under
  a PBKDF2-SHA256 key (600,000 iterations) from the user's passphrase. The CLI
  writes them to a file readable only by its owner. Anyone with the passphrase
  and the sealed key, or with the key file, can decrypt that user's data.
- **Account security** (sessions, OAuth, rate limits, email links) is described
  in [How the HE Engine works](docs/how-it-works.md#accounts-and-sessions).

## For operators

- Serve the site over HTTPS only (sessions use `Secure` cookies) behind the
  provided nginx configuration, and keep `TRUSTED_PROXIES` accurate.
- Keep `JWT_SECRET` and `METRICS_TOKEN` secret and long (`openssl rand`).
  Rotating `JWT_SECRET` signs everyone out.
- Backups contain users' server and public keys, the proof CRS and ciphertexts,
  but no secret keys. Protect them anyway: they reveal metadata and plain operands.
- Watch the RustSec and npm advisories (`cargo deny check`, `pnpm audit`) and
  Dependabot pull requests; CI fails on known vulnerabilities.
