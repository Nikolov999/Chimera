# Chimera Finding and Rule Contract v1

Schema: `chimera.finding/v1`

Rules consume normalized evidence and produce deterministic findings.

## Rule Identity

Every rule has a stable `CHM-*` rule ID and metadata describing category, severity, affected object, expected state, risk and remediation guidance.

## Finding Identity

Finding identity is deterministic for a rule and affected object. The same rule evaluated against the same object therefore retains identity across assessments even when evidence or timestamps change.

## Result States

- `PASS` — expectation satisfied
- `WARN` — weak or partial posture that does not meet failure criteria
- `FAIL` — evidence demonstrates the expectation is violated
- `UNKNOWN` — available evidence is insufficient for a defensible result

`UNKNOWN` is never silently converted to `PASS` or `FAIL`.

## Applicability

Applicability is tracked independently of status:

- `APPLICABLE`
- `NOT_APPLICABLE`
- `UNDETERMINED`

This preserves platform and context limitations explicitly.
