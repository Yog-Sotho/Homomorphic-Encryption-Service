# Getting help

## Read the documentation first

The documentation site, [https://yog-sotho.github.io/Homomorphic-Encryption-Service](https://yog-sotho.github.io/Homomorphic-Encryption-Service/), covers most questions:

- [User guide](https://yog-sotho.github.io/Homomorphic-Encryption-Service/user-guide/): the dashboard, keys, troubleshooting and a FAQ
- [How it works](https://yog-sotho.github.io/Homomorphic-Encryption-Service/how-it-works/): the keys, what the server can and cannot learn
- [Using the API](https://yog-sotho.github.io/Homomorphic-Encryption-Service/api/) and the [API reference](https://yog-sotho.github.io/Homomorphic-Encryption-Service/api-reference/): HTTP API, Rust SDK, `heaas` CLI
- [Self-hosting](https://yog-sotho.github.io/Homomorphic-Encryption-Service/self-hosting/): deployment, configuration, monitoring, backups

## Ask a question

Use [GitHub Discussions](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/discussions) for questions, ideas and help with a
deployment. Search first: someone may have asked already. Say which version you run
(`heaas params` or `GET /api/v1/he/params` shows it) and how you deployed it.

## Report a bug or request a feature

Open an [issue](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/issues/new/choose) with the matching form. A good bug report has
the version, what you did, what you expected and what happened instead, with the
server log lines around it (each response carries an `X-Request-Id` to search for).
Never paste secrets: `JWT_SECRET`, tokens, client keys or key files.

## Report a security vulnerability

Do **not** open a public issue. Report it privately as described in
[SECURITY.md](SECURITY.md).

## Support the project

To support the HE Engine's development, see
[Support the project](README.md#support-the-project): GitHub Sponsors or crypto tips.

## What to expect

The HE Engine is maintained on a best-effort basis by its author; there is no paid
support or service-level agreement. Fixes go into the latest release only.

TFHE-rs itself is Zama's project: questions about the cryptography library belong in
[its repository](https://github.com/zama-ai/tfhe-rs) or the
[Zama community forum](https://community.zama.ai/).
