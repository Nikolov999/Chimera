package filesystem

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const windowsCandidateEnvelopeSchemaVersion = 1

type windowsCandidateEnvelopeItem struct {
	CandidateID string `json:"candidate_id"`
	Path        string `json:"path"`
}

type windowsCandidateEnvelope struct {
	SchemaVersion int                            `json:"schema_version"`
	Items         []windowsCandidateEnvelopeItem `json:"items"`
}

func marshalWindowsCandidateEnvelope(items []windowsCandidateEnvelopeItem) ([]byte, error) {
	if err := validateWindowsCandidateItems(items); err != nil {
		return nil, err
	}
	envelope := windowsCandidateEnvelope{
		SchemaVersion: windowsCandidateEnvelopeSchemaVersion,
		Items:         append([]windowsCandidateEnvelopeItem(nil), items...),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("encode Windows candidate envelope: %w", err)
	}
	return raw, nil
}

func validateWindowsCandidateEnvelopeJSON(raw []byte) ([]windowsCandidateEnvelopeItem, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("decode Windows candidate envelope: %w", err)
	}
	versionRaw, ok := root["schema_version"]
	if !ok {
		return nil, fmt.Errorf("Windows candidate envelope missing schema_version")
	}
	var version int
	if err := json.Unmarshal(versionRaw, &version); err != nil {
		return nil, fmt.Errorf("Windows candidate envelope schema_version is invalid: %w", err)
	}
	if version != windowsCandidateEnvelopeSchemaVersion {
		return nil, fmt.Errorf("Windows candidate envelope schema_version=%d, want %d", version, windowsCandidateEnvelopeSchemaVersion)
	}
	itemsRaw, ok := root["items"]
	if !ok {
		return nil, fmt.Errorf("Windows candidate envelope missing items")
	}
	var items []windowsCandidateEnvelopeItem
	if err := json.Unmarshal(itemsRaw, &items); err != nil {
		return nil, fmt.Errorf("Windows candidate envelope items must be an array: %w", err)
	}
	if items == nil {
		return nil, fmt.Errorf("Windows candidate envelope items must be an array, not null")
	}
	if err := validateWindowsCandidateItems(items); err != nil {
		return nil, err
	}
	return items, nil
}

func validateWindowsCandidateItems(items []windowsCandidateEnvelopeItem) error {
	seen := make(map[string]struct{}, len(items))
	for i, item := range items {
		if strings.TrimSpace(item.CandidateID) == "" {
			return fmt.Errorf("Windows candidate envelope item %d missing candidate_id", i)
		}
		if strings.TrimSpace(item.Path) == "" {
			return fmt.Errorf("Windows candidate envelope item %d (%s) missing path", i, item.CandidateID)
		}
		if _, ok := seen[item.CandidateID]; ok {
			return fmt.Errorf("Windows candidate envelope contains duplicate candidate_id %q", item.CandidateID)
		}
		seen[item.CandidateID] = struct{}{}
	}
	return nil
}

func validWindowsCandidateEvidenceState(state evidence.State) bool {
	switch state {
	case evidence.StateObserved, evidence.StateDegraded, evidence.StateDenied, evidence.StateUnavailable, evidence.StateUnsupported, evidence.StateNotApplicable:
		return true
	default:
		return false
	}
}

// windowsCandidateEnvelopePowerShell deliberately decodes a schema envelope and
// emits each item as an individual pipeline object. Windows PowerShell 5.1 can
// preserve a top-level JSON array as one nested Object[] when ConvertFrom-Json is
// wrapped directly in @(...), which makes property access concatenate values
// from multiple candidates. The explicit .items boundary prevents that shape
// ambiguity and keeps candidate_id/path correlation one-to-one.
const windowsCandidateEnvelopePowerShell = `
function Read-ChimeraCandidateEnvelope {
 param(
  [Parameter(Mandatory=$true)][string]$Json,
  [Parameter(Mandatory=$true)][string]$Label
 )
 if([string]::IsNullOrWhiteSpace($Json)){throw ($Label+' candidate envelope is empty')}
 $root=ConvertFrom-Json -InputObject $Json -ErrorAction Stop
 if($null -eq $root){throw ($Label+' candidate envelope decoded to null')}
 $schemaProperty=$root.PSObject.Properties['schema_version']
 if($null -eq $schemaProperty){throw ($Label+' candidate envelope missing schema_version')}
 try{$schema=[int]$schemaProperty.Value}catch{throw ($Label+' candidate envelope schema_version is invalid: '+[string]$_.Exception.Message)}
 if($schema -ne 1){throw ($Label+' candidate envelope schema_version '+[string]$schema+' is unsupported')}
 $itemsProperty=$root.PSObject.Properties['items']
 if($null -eq $itemsProperty){throw ($Label+' candidate envelope missing items')}
 $rawItems=$itemsProperty.Value
 if($null -eq $rawItems -or -not ($rawItems -is [System.Array])){throw ($Label+' candidate envelope items must be a JSON array')}
 $validated=New-Object System.Collections.ArrayList
 $seen=@{}
 $index=0
 foreach($entry in $rawItems){
  if($null -eq $entry){throw ($Label+' candidate item '+[string]$index+' is null')}
  $idProperty=$entry.PSObject.Properties['candidate_id']
  $pathProperty=$entry.PSObject.Properties['path']
  if($null -eq $idProperty){throw ($Label+' candidate item '+[string]$index+' missing candidate_id')}
  if($null -eq $pathProperty){throw ($Label+' candidate item '+[string]$index+' missing path')}
  $candidateID=[string]$idProperty.Value
  $candidatePath=[string]$pathProperty.Value
  if([string]::IsNullOrWhiteSpace($candidateID)){throw ($Label+' candidate item '+[string]$index+' has empty candidate_id')}
  if([string]::IsNullOrWhiteSpace($candidatePath)){throw ($Label+' candidate '+$candidateID+' has empty path')}
  if($seen.ContainsKey($candidateID)){throw ($Label+' candidate envelope contains duplicate candidate_id '+$candidateID)}
  $seen[$candidateID]=$true
  [void]$validated.Add([pscustomobject]@{candidate_id=$candidateID;path=$candidatePath})
  $index++
 }
 foreach($entry in $validated){Write-Output $entry}
}
`
