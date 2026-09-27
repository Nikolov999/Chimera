# Chimera Architecture

Chimera is organized as a set of local evidence collectors, normalized domain models, deterministic assessment rules and output layers.

## Data Flow

```text
Host
  ↓
Collectors
  ↓
Normalized evidence / domain inventories
  ↓
Assessment profile
  ↓
Rule selection
  ↓
Rule evaluation
  ↓
Findings
  ↓
Prioritization / remediation grouping / reporting
```

## Main Areas

- `cmd/chimera` — process entry point
- `internal/app` — command routing and workflow composition
- `internal/cli` — global option parsing
- `internal/scan` — bounded assessment orchestration
- `internal/evidence` — normalized evidence model
- `internal/assessment` — deterministic rule catalog and evaluators
- `internal/profile` — built-in and custom assessment policy overlays
- `internal/selection` — deterministic rule/category filtering
- `internal/suppression` — auditable expiring finding suppressions
- `internal/prioritization` — deterministic risk ordering
- `internal/remediation` — remediation grouping and verification guidance
- `internal/report` / `internal/exporter` — report and machine-output serialization
- domain packages such as `processes`, `services`, `network`, `filesystem`, `accounts`, `storage`, `containers`, `persistence` and `secrets` — platform-aware collectors and models

## Collection Principles

1. Prefer local operating-system metadata and stable native interfaces.
2. Keep collection read-only.
3. Bound expensive work with explicit time and record limits.
4. Preserve partial/degraded evidence instead of inventing values.
5. Keep collection facts separate from assessment conclusions.
6. Keep machine output deterministic and free from ANSI/banner text.

## Platform Isolation

Platform-specific collection is implemented using OS-specific Go files and build constraints where appropriate. Shared normalized models allow rules and reports to operate over consistent data structures while preserving platform-specific applicability.
