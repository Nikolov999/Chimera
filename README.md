# Chimera

**Cross-platform live-host vulnerability, exposure, hardening and misconfiguration assessment engine**

Chimera is a terminal-first security assessment tool written in Go for Windows, Linux and macOS. It performs local, read-only evidence collection and evaluates the observed host against a deterministic rule set covering vulnerability exposure, configuration weaknesses, hardening posture and security-relevant system state.

The project is designed around a strict separation between **evidence collection** and **assessment logic**. Missing or permission-gated evidence remains explicit rather than being converted into guessed results.

## Highlights

- Cross-platform: Windows, Linux and macOS
- Single Go codebase with no third-party Go module dependencies
- Local and read-only assessment by default
- Evidence-backed deterministic findings
- Privilege-aware collection without self-elevation
- Vulnerability and end-of-life software correlation
- Process, service and scheduled-execution analysis
- Network listener, firewall and remote-management review
- Identity and authentication posture analysis
- Filesystem, ACL, storage and encryption posture
- Container, virtualization and developer-surface review
- Persistence and local secret-storage posture
- Profiles, rule selection and expiring suppressions
- Baselines and same-host assessment diffing
- JSON, structured text, CSV and SARIF-oriented export workflows
- Built-in health and contract validation through `chimera doctor`

## Safety Model

Chimera is intended for defensive assessment of systems you own or are explicitly authorized to inspect.

Normal assessment workflows are local and read-only. Chimera does not automatically elevate itself, exploit vulnerabilities, dump credentials, inject into processes, change security settings or perform remediation actions.

Network-backed intelligence refresh is an explicit maintenance action. Normal scans do not silently refresh intelligence.

## Build

Requirements:

- Go 1.22 or later

Clone and build:

```bash
git clone https://github.com/Nikolov999/chimera.git
cd chimera
go build -o chimera ./cmd/chimera
```

Windows PowerShell:

```powershell
go build -o chimera.exe ./cmd/chimera
.\chimera.exe --help
```

Linux/macOS:

```bash
chmod +x chimera
./chimera --help
```

## Core Workflows

```text
chimera
chimera --help
chimera scan
chimera baseline
chimera exposure
chimera hardening
chimera misconfigurations
chimera vulnerabilities
chimera findings
chimera finding <id>
chimera explain <id>
chimera evidence <id>
chimera relationships
chimera surface
chimera remediation
chimera report
chimera summary
chimera rules
chimera profiles
chimera doctor
```

### Full assessment

```bash
chimera scan
```

### Filter by severity

```bash
chimera scan --severity HIGH
```

### Filter by category

```bash
chimera scan --category network
```

### Machine-readable output

```bash
chimera scan --json --output assessment.json
```

### Create a baseline

```bash
chimera baseline --json --output baseline.json
```

### Compare assessments

```bash
chimera diff before.json after.json
```

### Inspect one finding

```bash
chimera finding CHM-F-<id>
chimera explain CHM-F-<id>
chimera evidence CHM-F-<id>
```

### Validate the local build/runtime

```bash
chimera doctor
```

## Observation Commands

Chimera also exposes focused read-only inventories for individual security domains:

```text
chimera overview
chimera kernel
chimera software
chimera processes
chimera services
chimera scheduled
chimera network
chimera firewall
chimera accounts
chimera filesystem
chimera storage
chimera containers
chimera persistence
chimera secrets
```

These commands are useful when the operator wants to inspect normalized evidence directly instead of running the complete assessment workflow.

## Global Options

Common options include:

```text
--json
--plain
--no-color
--quiet
--verbose
--offline
--timeout <duration>
--profile <name>
--severity <INFO|LOW|MEDIUM|HIGH|CRITICAL>
--category <name>
--include <selector>
--exclude <selector>
--output <path>
--config <path>
--max-workers <n>
--refresh-intelligence
```

`--refresh-intelligence` is explicit maintenance behavior and cannot be combined with `--offline`.

## Assessment Coverage

Chimera's assessment pipeline includes collectors and rules for:

- operating-system and kernel hardening
- installed software and runtime inventory
- vulnerability intelligence and software lifecycle/EOL state
- process trust, execution location, permissions, privilege and isolation
- executable-memory and loaded-module posture
- service configuration and path-integrity boundaries
- scheduled execution
- listening network endpoints and service attribution
- local firewall posture and exception breadth
- remote-management services
- SSH and SMB security posture
- local accounts and privileged identities
- Windows local security and credential-protection controls
- Linux sudo/PAM/login policy
- macOS authorization and FileVault/SecureToken context
- SSH key path permissions
- writable executables and privileged search paths
- sensitive files and ACL boundaries
- temporary-directory posture
- mount, volume, swap/pagefile and hibernation posture
- storage-encryption state
- Docker/containerd/Podman metadata
- Kubernetes and local orchestration configuration
- virtualization and developer surfaces
- persistence mechanisms
- local credential/configuration file permission posture

## Evidence and Findings

Collectors emit normalized evidence with explicit observation states such as observed, unavailable, denied or not applicable. Rules consume that evidence to produce deterministic findings.

Finding result states are:

- `PASS`
- `WARN`
- `FAIL`
- `UNKNOWN`

`UNKNOWN` is preserved when the available evidence is insufficient to support a defensible result.

See:

- [`docs/EVIDENCE_CONTRACT.md`](docs/EVIDENCE_CONTRACT.md)
- [`docs/FINDING_RULE_CONTRACT.md`](docs/FINDING_RULE_CONTRACT.md)
- [`docs/PRIVILEGE_CONTRACT.md`](docs/PRIVILEGE_CONTRACT.md)
- [`docs/PROFILE_CONTRACT.md`](docs/PROFILE_CONTRACT.md)
- [`docs/SELECTION_CONTRACT.md`](docs/SELECTION_CONTRACT.md)

## Configuration

An example configuration is provided at:

```text
examples/chimera.example.json
```

It demonstrates custom assessment profiles, expected services/ports and expiring suppressions.

## Repository Structure

```text
chimera/
├── cmd/
│   └── chimera/             # CLI entry point
├── internal/                # collectors, rules, contracts and renderers
├── docs/                    # public contracts and architecture notes
├── examples/                # example configuration
├── .gitignore
├── CHANGELOG.md
├── LICENSE
├── README.md
├── SECURITY.md
└── go.mod
```

## Architecture

At a high level:

```text
host state
   ↓
read-only collectors
   ↓
normalized evidence
   ↓
profile + rule selection
   ↓
deterministic assessment rules
   ↓
findings
   ↓
prioritization / remediation grouping
   ↓
CLI / JSON / report / export
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for more detail.

## Testing

The repository includes unit, contract and regression tests alongside the source.

```bash
go test ./...
```

Platform-specific behavior is isolated using Go build constraints and platform-specific implementations.

## Scope

Chimera is a defensive assessment engine. It is not an exploitation framework and intentionally does not provide credential dumping, persistence installation, remote compromise, destructive actions or automated privilege-escalation workflows.

## Version

Current public release: **v1.0.0**

## Author

Bobo Nikolov
