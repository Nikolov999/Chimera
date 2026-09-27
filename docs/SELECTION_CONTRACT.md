# Chimera Rule Selection Contract

Rule selection runs after profile policy is applied and before rule evaluation. Evidence collection remains independent of selection.

## Inputs

- `--severity <INFO|LOW|MEDIUM|HIGH|CRITICAL>`
- `--category <name>`
- `--include <selector>`
- `--exclude <selector>`

Selectors can identify exact rule IDs or exact categories. Unknown selectors fail closed rather than being interpreted fuzzily.

## Precedence

1. Exclusion wins.
2. Category filtering is applied.
3. Include allow-list filtering is applied.
4. Minimum effective severity is applied.
5. Remaining rules are evaluated.

Selection decisions remain auditable in machine-readable assessment output.
