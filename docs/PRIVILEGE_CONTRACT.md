# Chimera Privilege Context Contract v1

Schema: `chimera.privilege/v1`

The privilege context records how much local evidence the current Chimera process can observe without changing its execution identity.

## Principles

- Standard execution is valid.
- Elevated execution can expose deeper read-only evidence.
- Chimera does not invoke `sudo` automatically.
- Chimera does not trigger UAC elevation automatically.
- Chimera does not relaunch itself under a different identity.
- Administrative-group membership is not treated as proof that the current process is elevated.
- Permission-gated evidence remains explicit.

Elevation is an operator-controlled execution choice outside the collector. Read-only behavior remains the same when Chimera is started elevated.
