//go:build windows

package remotemgmt

import (
	"strings"
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestFix46WindowsSMBStagesAreIndependent(t *testing.T) {
	checks := []struct {
		name    string
		script  string
		stage   string
		command string
	}{
		{"server", windowsSMBServerConfigurationScript, windowsSMBStageServerConfiguration, "Get-SmbServerConfiguration"},
		{"shares", windowsSMBShareInventoryScript, windowsSMBStageShareInventory, "Get-SmbShare"},
		{"access", windowsSMBShareAccessScript, windowsSMBStageShareAccess, "Get-SmbShareAccess"},
		{"registry", windowsSMBRegistryPolicyScript, windowsSMBStageRegistryPolicy, "SMB registry policy"},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.script, "$stage='"+tc.stage+"'") {
				t.Fatalf("script missing stage %s", tc.stage)
			}
			if !strings.Contains(tc.script, "$commandName='"+tc.command+"'") {
				t.Fatalf("script missing command %s", tc.command)
			}
			for _, field := range []string{"Stage=$stage", "Command=$commandName", "Class=$class", "ExceptionType=$type", "Message=$message"} {
				if !strings.Contains(tc.script, field) {
					t.Fatalf("script missing structured failure field %q", field)
				}
			}
		})
	}
}

func TestFix46ShareInventoryKeepsExplicitSchemaStableFields(t *testing.T) {
	required := []string{
		"Name=[string]$s.Name",
		"Path=[string]$s.Path",
		"Description=[string]$s.Description",
		"EncryptData=[bool]$s.EncryptData",
		"FolderEnumerationMode=[string]$s.FolderEnumerationMode",
		"Special=[bool]$s.Special",
		"Temporary=[bool]$s.Temporary",
	}
	for _, fragment := range required {
		if !strings.Contains(windowsSMBShareInventoryScript, fragment) {
			t.Fatalf("Windows SMB SHARE_INVENTORY script missing explicit contract conversion %q", fragment)
		}
	}
	if strings.Contains(windowsSMBShareInventoryScript, "Select-Object Name,Path,Description,EncryptData,FolderEnumerationMode,Special,Temporary") {
		t.Fatal("Windows SMB provider must not serialize raw Get-SmbShare enum/property types")
	}
}

func TestFix46ShareAccessConsumesOnlySubmittedShareNames(t *testing.T) {
	if !strings.Contains(windowsSMBShareAccessScript, "CHIMERA_SMB_SHARE_ACCESS_JSON") {
		t.Fatal("SHARE_ACCESS must consume the explicit share-name envelope")
	}
	if strings.Contains(windowsSMBShareAccessScript, "Get-SmbShare -ErrorAction") {
		t.Fatal("SHARE_ACCESS must not re-run SHARE_INVENTORY")
	}
	if !strings.Contains(windowsSMBShareAccessScript, "Get-SmbShareAccess -Name $name") {
		t.Fatal("SHARE_ACCESS must correlate access evidence to submitted share names")
	}
}

func TestFix46StageFailureReasonContainsRequiredDiagnostics(t *testing.T) {
	f := &windowsSMBStageFailure{
		Stage:         windowsSMBStageServerConfiguration,
		Command:       "Get-SmbServerConfiguration",
		Class:         "PROVIDER_FAILURE",
		ExceptionType: "Example.Exception",
		Message:       "boom",
		Stderr:        "details",
		ExitCode:      7,
		Elapsed:       123 * time.Millisecond,
	}
	reason := f.reason()
	for _, want := range []string{
		"stage=SERVER_CONFIGURATION",
		"command=Get-SmbServerConfiguration",
		"class=PROVIDER_FAILURE",
		"exit_code=7",
		"elapsed_ms=123",
		"exception=Example.Exception",
		"message=boom",
		"stderr=details",
	} {
		if !strings.Contains(reason, want) {
			t.Fatalf("reason %q missing %q", reason, want)
		}
	}
}

func TestFix46IndependentSettingStagesPreserveSuccessfulServerEvidence(t *testing.T) {
	trueValue := true
	falseValue := false
	raw := windowsSMBJSON{Server: windowsSMBServerJSON{
		EnableSMB1Protocol:       &falseValue,
		EnableSMB2Protocol:       &trueValue,
		EnableSecuritySignature:  &trueValue,
		RequireSecuritySignature: &trueValue,
		EncryptData:              &falseValue,
		RejectUnencryptedAccess:  &trueValue,
	}}
	settings := windowsSMBSettings(raw, "", "stage=REGISTRY_POLICY class=PROVIDER_FAILURE", true, false)
	byName := map[string]SMBSetting{}
	for _, setting := range settings {
		byName[setting.Name] = setting
	}
	if got := byName["smb2_enabled"]; got.State != evidence.StateObserved || got.Value != "true" {
		t.Fatalf("successful SERVER_CONFIGURATION evidence lost: %+v", got)
	}
	if got := byName["allow_insecure_guest_auth"]; got.State != evidence.StateUnavailable || !strings.Contains(got.Reason, "REGISTRY_POLICY") {
		t.Fatalf("registry failure did not remain isolated: %+v", got)
	}
	if got := byName["null_session_shares"]; got.State != evidence.StateUnavailable || !strings.Contains(got.Reason, "REGISTRY_POLICY") {
		t.Fatalf("null-session shares must not become false observed zero after registry failure: %+v", got)
	}
}

func TestFix46ShareAccessFailureDoesNotDestroyShareInventory(t *testing.T) {
	raw := windowsSMBJSON{
		Shares:       []windowsSMBShareJSON{{Name: "Data", Path: `C:\Data`, FolderEnumerationMode: "AccessBased"}},
		AccessErrors: []string{"Data"},
	}
	shares := windowsSMBShares(raw)
	if len(shares) != 1 || shares[0].Name != "Data" {
		t.Fatalf("share inventory was lost: %+v", shares)
	}
	if shares[0].AccessKnown {
		t.Fatal("share access should be unknown after isolated SHARE_ACCESS failure")
	}
}

func TestFix46ParsesStructuredPowerShellFailure(t *testing.T) {
	stderr := []byte("noise\r\n{\"Stage\":\"SHARE_INVENTORY\",\"Command\":\"Get-SmbShare\",\"Class\":\"MODULE_UNAVAILABLE\",\"ExceptionType\":\"CommandNotFoundException\",\"Message\":\"missing\"}\r\n")
	d, ok := parseWindowsSMBStageDiagnostic(stderr)
	if !ok {
		t.Fatal("structured stage diagnostic was not parsed")
	}
	if d.Stage != windowsSMBStageShareInventory || d.Class != "MODULE_UNAVAILABLE" || d.Message != "missing" {
		t.Fatalf("unexpected diagnostic: %+v", d)
	}
}

func TestFix46ShareAccessFailurePreservesPerShareExceptionDetail(t *testing.T) {
	raw := windowsSMBJSON{
		Shares:         []windowsSMBShareJSON{{Name: "Data", Path: `C:\Data`}},
		AccessErrors:   []string{"Data"},
		AccessFailures: []windowsSMBAccessFailureJSON{{Name: "Data", ExceptionType: "Example.AccessException", Message: "denied by provider"}},
	}
	shares := windowsSMBShares(raw)
	if len(shares) != 1 {
		t.Fatalf("shares=%d want 1", len(shares))
	}
	if shares[0].AccessKnown {
		t.Fatal("access should be unknown")
	}
	if !strings.Contains(shares[0].Reason, "Example.AccessException") || !strings.Contains(shares[0].Reason, "denied by provider") {
		t.Fatalf("share reason lost stage exception detail: %q", shares[0].Reason)
	}
}
