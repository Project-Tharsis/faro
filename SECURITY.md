# Security Model

## What Faro Does

Faro is a **heuristic pattern-based scanner** for Hermes Agent skills and plugins.
It runs 19 regex-based checks across 5 categories to flag potentially dangerous
code patterns before a skill becomes active.

## What Faro Does NOT Do

- **NOT a sandbox** — Faro never executes skill code, analyzes call graphs,
  or traces runtime behavior
- **NOT a static analyzer** — No AST parsing, no control flow analysis,
  no taint tracking
- **NOT a guarantee of safety** — A clean scan means no patterns matched,
  not that the skill is provably safe. False negatives are possible.
- **NOT a replacement for manual review** — Always review scan results
  and source code of third-party skills yourself

## Threat Model

Faro protects against **accidental or negligent installation of dangerous
Hermes skills/plugins**, such as:

- Skills that read browser cookies or OS keychain
- Skills that modify `~/.hermes/config.yaml` to alter agent behavior
- Skills with hardcoded API keys or credentials
- Skills that execute arbitrary shell commands via subprocess
- Skills that register persistence mechanisms (cron, systemd)

Faro does NOT protect against:

- Deliberately obfuscated malicious code (e.g., base64-encoded exec)
- Vulnerabilities in trusted skills that are already in the manifest
- Supply chain attacks on skill dependencies
- Skills that appear benign but have malicious intent at runtime

## Shallow vs Deep Checks

- **Shallow (default, used by hook)**: Compares file structure hash.
  Detects added/removed/renamed files. Does NOT detect content changes
  within existing files. Fast enough for every LLM call.
- **Deep (`faro check --deep`)**: Also compares content hash of
  .py, .sh, .js, .ts files. Detects code changes after approval.
  Use for periodic audits or before approving major changes.

## Reporting a Vulnerability

If you discover a security issue in Faro itself, please open a GitHub issue
with the `security` label. Do NOT disclose vulnerabilities in third-party
skills through Faro's issue tracker — report those to the skill author.

For urgent issues, contact the maintainer directly.

## Platform Support

The pre_llm_call hook injects warnings into the conversation on **Feishu**.
On other platforms (Telegram, Discord, CLI, etc.), it writes to stderr for
log visibility only — no conversation injection. This is because the hook
needs the user to be able to act on the alert, and Feishu is the primary
interactive platform for Faro's maintainers.

## Known Limitations

1. Regex patterns can produce false positives (e.g., documentation
   mentioning `eval()` triggers the check)
2. Content hash only covers .py/.sh/.js/.ts — changes in .md, .yaml,
   or binary files are not detected by deep checks
3. Manifest atomicity is best-effort — concurrent writes from multiple
   processes may race (single-user design)

## Development Safety

**Tests are isolated.** All integration tests (`tests/test_staging.py`) use
a `FARO_HOME` environment variable to redirect `.hermes/` paths to a
`tempfile.TemporaryDirectory`. Real `~/.hermes` is never touched during
`pytest`. Contributors can run the full suite locally without risk.

To manually override the home directory:
```bash
FARO_HOME=/tmp/faro-test faro scan --staged
```

## Version

Faro 0.x — no stability guarantees. The manifest schema, CLI interface,
and scan patterns may change without notice between minor versions.
