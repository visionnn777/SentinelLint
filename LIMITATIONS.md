# SentinelLint — Scope & Limitations

SentinelLint is a lightweight SIH project, not a compiler-grade or enterprise SAST replacement. These limits are intentional and should be stated honestly during judging.

## Analysis depth

- Python uses the standard-library `ast` module.
- C++ uses a lightweight tokenizer and structural parser, not Clang's full semantic AST.
- Taint analysis is intra-procedural with bounded same-file direct call flow.
- There is no full cross-file or return-value summary engine.
- C++ lifetime/type reasoning is conservative and heuristic.

## Auto-fix

Fixes are deterministic and re-parsed before writing. This validates syntax/rule behavior; it does **not** prove semantic equivalence of the whole program.

## Accuracy claims

The published 100% precision and recall are only for the current annotated regression corpus:

```text
34 expected detections
0 safe-corpus findings
0 malformed-input crashes
```

These figures are not universal guarantees for arbitrary repositories.

## C++ scope

The custom parser is chosen to preserve a dependency-free/local-first build. For deeper production-grade C++ analysis, a compiler-backed frontend such as Clang would be a future extension.

## Integrations

The local analyzer/dashboard can run without internet. GitHub Actions and SARIF upload are optional networked integrations; they are not required for the local workflow.
