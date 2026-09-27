package evidencequality

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestClassifyReleaseBlockingLimitations(t *testing.T) {
	cases := []string{
		"provider services stopped at the reserved collection budget: context deadline exceeded",
		"provider filesystem typed inventory validation failed: filesystem temporary-directory record 0 is incomplete",
		"windows-defender-firewall: exit status 1",
		"windows-executable-dacl-inventory failed (exit code 1)",
		"SMB setting signing_required: invalid Windows SMB provider JSON",
		"decode Windows SMB provider output: json: cannot unmarshal number into Go struct field .Shares.FolderEnumerationMode of type string",
	}
	for _, reason := range cases {
		got := Classify(reason)
		if !got.ReleaseBlocker {
			t.Fatalf("%q classified as %s without release blocker", reason, got.Class)
		}
		if got.CanonicalKey == "" {
			t.Fatalf("%q has no canonical release-blocker key", reason)
		}
	}
}

func TestClassifyExpectedLimitationsDoNotBlock(t *testing.T) {
	cases := []struct {
		reason string
		want   LimitationClass
	}{
		{"docker CLI is unavailable", ClassOptionalProvider},
		{"credential-guard-lsa-config: registry value is absent; no deterministic Windows default is inferred", ClassExpectedEnvironment},
		{"cross-process environment inspection would require reading another process environment block; Chimera intentionally does not read process memory", ClassExpectedEnvironment},
		{"access denied while reading service metadata", ClassPermission},
		{"containerd instance enumeration is not applicable on Windows", ClassNotApplicable},
	}
	for _, tc := range cases {
		got := Classify(tc.reason)
		if got.Class != tc.want || got.ReleaseBlocker {
			t.Fatalf("%q = class %s blocker=%v, want %s false", tc.reason, got.Class, got.ReleaseBlocker, tc.want)
		}
	}
}

func TestFix27CanonicalReleaseBlockersDeduplicateProviderAliases(t *testing.T) {
	reasons := []string{
		"process.source.windows_loaded_modules: exit status 1",
		"process: process.source.windows_loaded_modules: exit status 1",
		"windows-loaded-modules: exit status 1",
	}
	items, summary := ClassifyAll(reasons)
	if len(items) != 1 {
		t.Fatalf("canonical items=%d want 1", len(items))
	}
	if summary.ProductDefect != 3 {
		t.Fatalf("product defect limitation occurrences=%d want 3", summary.ProductDefect)
	}
	if summary.ReleaseBlockers != 1 {
		t.Fatalf("unique release blockers=%d want 1", summary.ReleaseBlockers)
	}
	if items[0].CanonicalKey == "" || items[0].Occurrences != 3 {
		t.Fatalf("unexpected canonical limitation: %#v", items[0])
	}
}

func TestFix27SMBProviderJSONFailuresShareOneCanonicalBlocker(t *testing.T) {
	reasons := []string{
		"SMB setting signing_required: invalid Windows SMB provider JSON",
		"network: smb_security.setting.server.signing_required: invalid Windows SMB provider JSON",
		"decode Windows SMB provider output: json: cannot unmarshal number into Go struct field .Shares.FolderEnumerationMode of type string",
	}
	items, summary := ClassifyAll(reasons)
	if summary.ReleaseBlockers != 1 {
		t.Fatalf("unique release blockers=%d want 1", summary.ReleaseBlockers)
	}
	if len(items) != 1 || items[0].Class != ClassProductDefect || !items[0].ReleaseBlocker {
		t.Fatalf("unexpected SMB aggregation: %#v", items)
	}
	if items[0].CanonicalKey != "PRODUCT_DEFECT:windows-smb-provider-json" || items[0].Occurrences != 3 {
		t.Fatalf("SMB canonical item=%#v", items[0])
	}
}

func TestFix27DistinctProvidersRemainDistinctReleaseBlockers(t *testing.T) {
	reasons := []string{
		"windows-loaded-modules: exit status 1",
		"windows-executable-dacl-inventory failed (exit code 1)",
		"SMB setting signing_required: invalid Windows SMB provider JSON",
	}
	_, summary := ClassifyAll(reasons)
	if summary.ReleaseBlockers != 3 {
		t.Fatalf("unique release blockers=%d want 3", summary.ReleaseBlockers)
	}
}

func TestFix33RecordScopedLimitationsAggregateAffectedRecords(t *testing.T) {
	reasons := []string{
		"persistence.privilege.per-0552fcae934d0a60b4a3: local-account privilege inventory is unavailable",
		"persistence.privilege.per-05fb7b6b8866b4fa93ca: local-account privilege inventory is unavailable",
		"persistence: persistence.privilege.per-0552fcae934d0a60b4a3: local-account privilege inventory is unavailable",
	}
	items, summary := ClassifyAll(reasons)
	if len(items) != 1 {
		t.Fatalf("items=%d want 1: %#v", len(items), items)
	}
	if items[0].Occurrences != 3 || items[0].AffectedRecords != 2 {
		t.Fatalf("aggregation=%#v", items[0])
	}
	if len(items[0].AffectedRecordIDs) != 2 || items[0].AffectedRecordIDs[0] >= items[0].AffectedRecordIDs[1] {
		t.Fatalf("affected record ids are not preserved deterministically: %#v", items[0].AffectedRecordIDs)
	}
	if summary.TotalOccurrences != 3 || summary.UniqueLimitations != 1 || summary.AffectedRecords != 2 {
		t.Fatalf("summary=%#v", summary)
	}
}

func TestFix33PermissionRestrictedProcessLimitationsClassifyAsPermission(t *testing.T) {
	got := Classify("process.source.windows_virtualqueryex: 25 process mapping record(s) permission-restricted")
	if got.Class != ClassPermission || got.ReleaseBlocker {
		t.Fatalf("classification=%#v", got)
	}
}

func TestFix40NestedServiceAliasesShareOneRootCause(t *testing.T) {
	raw, err := os.ReadFile("testdata/nested_aliases.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Reasons []string `json:"reasons"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	items, summary := ClassifyAll(fixture.Reasons)
	if len(items) != 1 {
		t.Fatalf("canonical items=%d want 1: %#v", len(items), items)
	}
	item := items[0]
	if !item.ReleaseBlocker || item.Class != ClassDeadlineBudget {
		t.Fatalf("classification=%#v", item)
	}
	if item.RootCauseID == "" || item.RootCauseID != item.CanonicalKey {
		t.Fatalf("root cause identity=%q canonical=%q", item.RootCauseID, item.CanonicalKey)
	}
	if item.Provider != "windows-service-security" || item.Stage != "enrichment" || item.Platform != "windows" {
		t.Fatalf("root metadata=%#v", item)
	}
	if item.ErrorCode != "context-deadline-exceeded" || item.Message != "context deadline exceeded" {
		t.Fatalf("root error metadata=%#v", item)
	}
	if item.Occurrences != len(fixture.Reasons) || len(item.Aliases) != len(fixture.Reasons) {
		t.Fatalf("alias accounting=%#v", item)
	}
	if !reflect.DeepEqual(item.AffectedCategories, []string{"persistence", "services"}) {
		t.Fatalf("affected categories=%#v", item.AffectedCategories)
	}
	if summary.ReleaseBlockers != 1 || summary.UniqueReleaseBlockers != 1 {
		t.Fatalf("release blocker summary=%#v", summary)
	}
	if summary.TotalOccurrences != len(fixture.Reasons) || summary.UniqueLimitations != 1 {
		t.Fatalf("raw/unique accounting=%#v", summary)
	}
}

func TestFix40IndependentProviderStagesRemainDistinct(t *testing.T) {
	reasons := []string{
		"process.source.windows_loaded_modules: windows-loaded-modules-enumeration: context deadline exceeded",
		"process.source.windows_loaded_modules: windows-loaded-modules-enrichment: context deadline exceeded",
		"provider network collector deadline reached: context deadline exceeded",
	}
	items, summary := ClassifyAll(reasons)
	if len(items) != 3 || summary.ReleaseBlockers != 3 || summary.UniqueReleaseBlockers != 3 {
		t.Fatalf("distinct stage accounting items=%d summary=%#v items=%#v", len(items), summary, items)
	}
	seen := map[string]bool{}
	for _, item := range items {
		if seen[item.RootCauseID] {
			t.Fatalf("duplicate root cause id %q", item.RootCauseID)
		}
		seen[item.RootCauseID] = true
	}
}

func TestFix40ProductDefectContractFailuresBlock(t *testing.T) {
	cases := []struct {
		reason string
		code   string
	}{
		{"windows-temp-security candidate contract failed: duplicate candidate_id", "candidate-contract"},
		{"windows-executable-dacl structural validation failed: provider returned impossible schema", "structural-inventory-validation"},
		{"windows-service-registry-acl provider launch failed: executable not started", "provider-launch-failed"},
		{"windows-executable-dacl unexpected zero-result contract violation with 25 submitted candidates", "zero-result-contract"},
	}
	for _, tc := range cases {
		got := Classify(tc.reason)
		if got.Class != ClassProductDefect || !got.ReleaseBlocker {
			t.Fatalf("%q classified %#v", tc.reason, got)
		}
		if got.RootCauseID == "" || got.ErrorCode != tc.code {
			t.Fatalf("%q metadata %#v", tc.reason, got)
		}
	}
}

func TestFix40ExpectedWindowsRestrictionsRemainNonBlocking(t *testing.T) {
	cases := []string{
		"windows-loaded-modules: access denied for protected process",
		"windows-loaded-modules: process exited during collection",
		"credential-guard-lsa-config: registry value is absent; no deterministic Windows default is inferred",
		"docker CLI is unavailable",
	}
	for _, reason := range cases {
		got := Classify(reason)
		if got.ReleaseBlocker {
			t.Fatalf("expected environmental limitation became blocker: %q => %#v", reason, got)
		}
	}
}

func TestFix40LiveServiceTimeoutAliasesCanonicalize(t *testing.T) {
	reasons := []string{
		"persistence.source.services: service path-integrity collection deadline reached: context deadline exceeded; windows-service-account-security: windows-service-security-enrichment: context deadline exceeded; windows-service-object-security: windows-service-security-enrichment: context deadline exceeded; windows-service-path-integrity: no Windows service records were available for path-integrity correlation; windows-service-path-security: windows-service-security-enrichment: context deadline exceeded; windows-service-recovery-security: windows-service-security-enrichment: context deadline exceeded; windows-service-registry-security: windows-service-security-enrichment: context deadline exceeded; windows-service-security: windows-service-security-enrichment: context deadline exceeded",
		"windows-service-object-security: windows-service-security-enrichment: context deadline exceeded",
		"windows-service-path-security: windows-service-security-enrichment: context deadline exceeded",
		"windows-service-registry-security: windows-service-security-enrichment: context deadline exceeded",
		"service.source.windows_service_account_security: windows-service-security-enrichment: context deadline exceeded",
	}
	items, summary := ClassifyAll(reasons)
	if len(items) != 1 || summary.ReleaseBlockers != 1 {
		t.Fatalf("live aliases did not collapse: summary=%#v items=%#v", summary, items)
	}
	if !strings.Contains(items[0].RootCauseID, "windows-service-security:enrichment") {
		t.Fatalf("unexpected live root cause %q", items[0].RootCauseID)
	}
}

func TestFix46StructuredSMBStageClassesRemainReleaseSafe(t *testing.T) {
	product := Classify("stage=SHARE_INVENTORY command=Get-SmbShare class=PROVIDER_FAILURE exit_code=1 elapsed_ms=42 message=RPC failure")
	if product.Class != ClassProductDefect || !product.ReleaseBlocker {
		t.Fatalf("provider failure classified as %+v", product)
	}
	optional := Classify("stage=SERVER_CONFIGURATION command=Get-SmbServerConfiguration class=MODULE_UNAVAILABLE exit_code=3 elapsed_ms=2 message=cmdlet unavailable")
	if optional.Class != ClassOptionalProvider || optional.ReleaseBlocker {
		t.Fatalf("module absence classified as %+v", optional)
	}
	deadline := Classify("stage=SHARE_ACCESS command=Get-SmbShareAccess class=DEADLINE exit_code=-1 elapsed_ms=26000 message=context deadline exceeded")
	if deadline.Class != ClassDeadlineBudget || !deadline.ReleaseBlocker {
		t.Fatalf("deadline classified as %+v", deadline)
	}
}

func TestFix46StructuredSMBStageAliasesCollapseToOneRootCause(t *testing.T) {
	reasons := []string{
		"SMB setting smb1_enabled: provider=windows-smb stage=SERVER_CONFIGURATION command=Get-SmbServerConfiguration class=PROVIDER_FAILURE exit_code=1 elapsed_ms=50 message=RPC failure",
		"SMB setting smb2_enabled: provider=windows-smb stage=SERVER_CONFIGURATION command=Get-SmbServerConfiguration class=PROVIDER_FAILURE exit_code=1 elapsed_ms=50 message=RPC failure",
		"SMB setting signing_required: provider=windows-smb stage=SERVER_CONFIGURATION command=Get-SmbServerConfiguration class=PROVIDER_FAILURE exit_code=1 elapsed_ms=50 message=RPC failure",
	}
	items, summary := ClassifyAll(reasons)
	if summary.ReleaseBlockers != 1 || summary.UniqueReleaseBlockers != 1 {
		t.Fatalf("release blockers=%d unique=%d want 1/1", summary.ReleaseBlockers, summary.UniqueReleaseBlockers)
	}
	if len(items) != 1 {
		t.Fatalf("unique limitations=%d want 1: %+v", len(items), items)
	}
	if items[0].Provider != "windows-smb" || items[0].Stage != "server-configuration" {
		t.Fatalf("root metadata=%+v", items[0])
	}
	if items[0].RootCauseID != "PRODUCT_DEFECT:windows-smb:server-configuration:provider-stage" {
		t.Fatalf("root cause=%q", items[0].RootCauseID)
	}
	if items[0].Occurrences != 3 {
		t.Fatalf("occurrences=%d want 3", items[0].Occurrences)
	}
}

func TestFix48PropagatedWindowsDependencyAliasesUseDeepestRootCause(t *testing.T) {
	reasons := []string{
		"network: provider=network stage=collector class=DEADLINE message=context deadline exceeded",
		"firewall: provider=firewall stage=collection class=DEADLINE upstream provider=network stage=collector class=DEADLINE message=context deadline exceeded",
		"remote-management: provider=remote-management stage=collection class=DEADLINE upstream provider=network stage=collector class=DEADLINE message=context deadline exceeded",
	}
	items, summary := ClassifyAll(reasons)
	if summary.UniqueReleaseBlockers != 1 || summary.ReleaseBlockers != 1 {
		t.Fatalf("propagated dependency aliases were not collapsed: summary=%#v items=%#v", summary, items)
	}
	if len(items) != 1 {
		t.Fatalf("unique limitations=%d want 1: %#v", len(items), items)
	}
	got := items[0]
	if got.Provider != "network" || got.Stage != "collector" {
		t.Fatalf("deepest provider/stage=%s/%s want network/collector", got.Provider, got.Stage)
	}
	if got.RootCauseID != "DEADLINE_BUDGET:network:collector:deadline-budget" {
		t.Fatalf("root cause=%q", got.RootCauseID)
	}
	if got.Occurrences != 3 {
		t.Fatalf("occurrences=%d want 3", got.Occurrences)
	}
}

func TestFix48PropagatedStructuredSMBAliasUsesDeepestStage(t *testing.T) {
	reasons := []string{
		"network: provider=windows-smb stage=SERVER_CONFIGURATION class=PROVIDER_FAILURE exit_code=1 message=RPC failure",
		"remote-management: provider=remote-management stage=collection class=PROVIDER_FAILURE upstream provider=windows-smb stage=SERVER_CONFIGURATION class=PROVIDER_FAILURE exit_code=1 message=RPC failure",
	}
	items, summary := ClassifyAll(reasons)
	if len(items) != 1 || summary.UniqueReleaseBlockers != 1 {
		t.Fatalf("SMB aliases were not collapsed: summary=%#v items=%#v", summary, items)
	}
	if items[0].Provider != "windows-smb" || items[0].Stage != "server-configuration" {
		t.Fatalf("SMB root metadata=%#v", items[0])
	}
}
