# Security Policy & Responsible Use

## ⚠️ Authorized Use Only

This toolkit — `prompt-injection-security` — is a **defensive security testing framework**. It sends adversarial prompt-injection payloads (jailbreaks, system-prompt extraction, encoding bypasses, multi-stage social engineering) to language models.

You **MAY** use it only against systems that you **own or have explicit written authorization to test**, including:

- Models you run locally (e.g., your own Ollama instances).
- Models behind APIs you control or have been authorized to assess (your own app, a customer engagement under a signed SOW, an approved bug-bounty scope).
- Educational labs, CTF challenges, and your own research models.

You **MAY NOT** use it to:

- Attack third-party production services without authorization.
- Extract real secrets, PII, or proprietary prompts from systems you do not own.
- Enable abuse, harassment, or unauthorized access.

The authors do not condone unauthorized use and accept no liability for misuse. **The responsibility to obtain authorization rests entirely with the operator.**

## Canary tokens & injected system prompts

The `--canary` / `--secret-canary` features inject a confidential token into the target's system prompt to measure extraction resistance. Only ever run this against models **you control** — never inject canaries into third-party systems.

## Reporting a vulnerability in this tool itself

Found a security issue **in this codebase** (not in a model you are testing)? Please report it privately:

- **Do not** open a public GitHub issue for security-sensitive bugs.
- Email the maintainer (see the repo's primary contact) with a description and reproduction.
- We aim to acknowledge within 72 hours and coordinate a fix before public disclosure.

## Scope of "security" for this tool

This is a testing/detection tool, not a backdoor. There is no telemetry, no data exfiltration, and no network calls beyond the target endpoint you explicitly configure (validated to `http`/`https` only — see `_validate_base_url`). API keys are read from environment variables and are never written to report files.
