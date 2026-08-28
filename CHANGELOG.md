# Changelog

## SIH v6 — Final

- 42 rules: 25 Python + 17 C++.
- Added SSRF, sensitive logging, insecure temporary files, permissive permissions and tar extraction checks.
- Added C++ use-after-free, double-free, uninitialized-use, uncontrolled-allocation and null-dereference checks.
- Added bounded same-file cross-function taint with `[call]` evidence edges.
- Added sink-aware sanitizer handling and conservative branch merging.
- Added baseline stability, ignore/suppression support and strict `PARTIAL`/`ERROR` CI semantics.
- Added deterministic auto-fix validation and re-scan workflow.
- Added JSON, HTML and SARIF 2.1.0 output and GitHub Actions integration.
- Added local browser dashboard.
- Added safe/vulnerable/edge/malformed regression corpus and hardening checks.

## Cleanup

- Shared credential/naming patterns moved to `analyzer/core/patterns.py`.
- Rule metadata construction simplified.
- Generated `__pycache__`/`.pyc` files removed from the source package.
- Documentation consolidated into short operational guides.
