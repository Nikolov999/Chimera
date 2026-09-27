//go:build windows

package secrets

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func platformPermissionModel() string { return "WINDOWS_DACL" }
func applyBasicPermissionMetadata(r *Record, info os.FileInfo) {
	if r == nil || info == nil {
		return
	}
	r.Mode = info.Mode().String()
	r.PermissionState = "UNKNOWN"
}

type winACLResult struct {
	Path       string `json:"path"`
	State      string `json:"state"`
	Owner      string `json:"owner"`
	BroadRead  bool   `json:"broad_read"`
	BroadWrite bool   `json:"broad_write"`
	Reason     string `json:"reason"`
}

const winACLScript = `$paths=ConvertFrom-Json $env:CHIMERA_SECRET_PATHS_JSON
$wd=@('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-32-546')
foreach($p in $paths){
 try {
  $acl=Get-Acl -LiteralPath $p -ErrorAction Stop
  $br=$false;$bw=$false
  foreach($a in $acl.Access){
   if($a.AccessControlType -ne 'Allow'){continue}
   $sid=$a.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
   if($wd -notcontains $sid){continue}
   $rights=[string]$a.FileSystemRights
   if($rights -match 'Read|ReadAndExecute|FullControl|Modify'){ $br=$true }
   if($rights -match 'Write|Modify|FullControl|CreateFiles|CreateDirectories|WriteData|AppendData'){ $bw=$true }
  }
  [pscustomobject]@{path=$p;state='OBSERVED';owner=[string]$acl.Owner;broad_read=$br;broad_write=$bw;reason=''}|ConvertTo-Json -Compress
 } catch {
  $st=if($_.Exception -is [System.UnauthorizedAccessException]){'DENIED'}else{'UNAVAILABLE'}
  [pscustomobject]@{path=$p;state=$st;owner='';broad_read=$false;broad_write=$false;reason=[string]$_.Exception.Message}|ConvertTo-Json -Compress
 }
}`

func enrichPlatformPermissions(ctx context.Context, records []Record) []string {
	if len(records) == 0 {
		return nil
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		ps, err = exec.LookPath("pwsh.exe")
	}
	if err != nil {
		return []string{"secret permission enrichment unavailable: PowerShell not found"}
	}

	const batchSize = 64
	limitations := []string{}
	candidateIndexes := make([]int, 0, len(records))
	for i := range records {
		if records[i].Exists {
			candidateIndexes = append(candidateIndexes, i)
		}
	}
	completed := 0
	for offset := 0; offset < len(candidateIndexes); offset += batchSize {
		if ctx != nil && ctx.Err() != nil {
			limitations = append(limitations, fmt.Sprintf("secret permission enrichment stopped after %d of %d candidate(s): %v", completed, len(candidateIndexes), ctx.Err()))
			break
		}
		end := offset + batchSize
		if end > len(candidateIndexes) {
			end = len(candidateIndexes)
		}
		indexes := candidateIndexes[offset:end]
		paths := make([]string, 0, len(indexes))
		by := make(map[string]int, len(indexes))
		for _, i := range indexes {
			paths = append(paths, records[i].Path)
			by[strings.ToLower(filepath.Clean(records[i].Path))] = i
		}
		rawPaths, marshalErr := json.Marshal(paths)
		if marshalErr != nil {
			limitations = append(limitations, "secret permission enrichment input encode failed: "+marshalErr.Error())
			continue
		}
		cmd := exec.CommandContext(ctx, ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", winACLScript)
		cmd.Env = append(os.Environ(), "CHIMERA_SECRET_PATHS_JSON="+string(rawPaths))
		raw, runErr := cmd.Output()

		seen := map[int]struct{}{}
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var x winACLResult
			if json.Unmarshal([]byte(line), &x) != nil {
				continue
			}
			i, ok := by[strings.ToLower(filepath.Clean(strings.TrimSpace(x.Path)))]
			if !ok {
				continue
			}
			seen[i] = struct{}{}
			r := &records[i]
			r.PermissionState = normalizeWord(x.State)
			r.OwnerID = strings.TrimSpace(x.Owner)
			if r.PermissionState == "OBSERVED" {
				r.WorldReadable = boolTri(x.BroadRead)
				r.WorldWritable = boolTri(x.BroadWrite)
				r.GroupReadable = r.WorldReadable
				r.GroupWritable = r.WorldWritable
				r.BroadlyAccessible = r.WorldReadable
				r.BroadlyWritable = r.WorldWritable
			}
			if r.PermissionState == "DENIED" {
				r.State = "DENIED"
				r.Reason = x.Reason
			}
			if r.PermissionState == "UNAVAILABLE" && r.State == "OBSERVED" {
				r.Reason = x.Reason
			}
		}
		completed += len(seen)
		if scanErr := sc.Err(); scanErr != nil {
			limitations = append(limitations, "secret permission enrichment output parse degraded: "+scanErr.Error())
		}
		if runErr != nil {
			reason := runErr.Error()
			if ctx != nil && ctx.Err() != nil {
				reason = ctx.Err().Error()
			}
			limitations = append(limitations, fmt.Sprintf("secret permission enrichment preserved %d completed candidate(s) before batch interruption: %s", completed, reason))
			break
		}
	}
	return uniqueSorted(limitations)
}

func boolTri(v bool) string {
	if v {
		return "TRUE"
	}
	return "FALSE"
}
