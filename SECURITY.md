# Security Policy

## Intended Use

Chimera is intended for defensive assessment of systems you own or are explicitly authorized to inspect.

Normal assessment workflows are designed to be local and read-only. Operators remain responsible for authorization, configuration and handling of generated assessment data.

## Sensitive Output

Assessment output can contain security-relevant host metadata, paths, account names, service information and configuration state. Treat generated reports and JSON exports as potentially sensitive.

Do not commit real assessment output from production or third-party systems to a public repository.

## Reporting a Security Issue

Do not publish exploitable security defects or sensitive host data in a public issue. Use a private disclosure channel available through the repository owner before public discussion.
