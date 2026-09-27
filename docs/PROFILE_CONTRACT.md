# Chimera Assessment Profile Contract

Assessment profiles are policy overlays applied after normalized evidence is collected and before rule evaluation. Profiles do not alter raw evidence.

## Built-in Profiles

- `default`
- `workstation`
- `server`
- `developer`
- `high-security`
- `minimal`

Profiles can control applicability and severity floors while preserving stable rule/finding identity. Custom profiles can extend built-in profiles and define expected services, expected ports and approved exceptions.

See `examples/chimera.example.json` for a configuration example.
