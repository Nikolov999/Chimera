# Chimera Evidence Contract v1

Schema: `chimera.evidence/v1`

The evidence contract is the stable boundary between collectors and assessment logic. Collectors gather facts; rules evaluate those facts.

## Observation Shape

```json
{
  "key": "host.kernel",
  "state": "OBSERVED",
  "value": "6.x.y",
  "source": "uname -r",
  "collected_at": "2026-01-01T00:00:00Z",
  "confidence": "HIGH"
}
```

When a value cannot be observed, the record carries an explicit state and reason rather than a guessed value.

## Requirements

A collector must:

1. emit stable evidence keys;
2. record the source of each fact;
3. record collection time;
4. preserve observed values when available;
5. use explicit non-normal states when evidence is unavailable;
6. retain degradation/error reasons;
7. assign evidence confidence independently of rule severity;
8. never substitute guessed values for missing evidence;
9. avoid duplicate keys inside one normalized evidence set.

Keys are lowercase, stable and dot-separated. They describe observed facts rather than desired security posture.
