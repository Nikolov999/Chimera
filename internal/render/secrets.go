package render

import (
	"fmt"
	"io"

	secretinv "github.com/Nikolov999/chimera/internal/secrets"
)

func SecretsHuman(w io.Writer, inv secretinv.Inventory, verbose bool) {
	fmt.Fprintln(w, "SECRET-STORAGE POSTURE")
	fmt.Fprintf(w, "  Schema             %s\n", inv.Schema)
	fmt.Fprintf(w, "  Collector          %s\n", inv.CollectorVersion)
	fmt.Fprintf(w, "  Platform           %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Collected          %s\n", inv.CollectedAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Records            %d\n", inv.Summary.Records)
	fmt.Fprintf(w, "  Files/dirs         %d / %d\n", inv.Summary.Files, inv.Summary.Directories)
	fmt.Fprintf(w, "  Environment files  %d\n", inv.Summary.EnvironmentFiles)
	fmt.Fprintf(w, "  Cloud configs      %d\n", inv.Summary.CloudConfigs)
	fmt.Fprintf(w, "  Private keys       %d\n", inv.Summary.PrivateKeys)
	fmt.Fprintf(w, "  Service configs    %d\n", inv.Summary.ServiceConfigs)
	fmt.Fprintf(w, "  Shell histories    %d\n", inv.Summary.ShellHistories)
	fmt.Fprintf(w, "  Credential stores  %d\n", inv.Summary.CredentialStores)
	fmt.Fprintf(w, "  Orchestration      %d\n", inv.Summary.OrchestrationConfigs)
	fmt.Fprintf(w, "  Developer creds    %d\n", inv.Summary.DeveloperCredentials)
	fmt.Fprintf(w, "  Permission checked %d\n", inv.Summary.PermissionAssessed)
	fmt.Fprintf(w, "  Broadly accessible %d\n", inv.Summary.BroadlyAccessible)
	fmt.Fprintf(w, "  Broadly writable   %d\n", inv.Summary.BroadlyWritable)
	fmt.Fprintf(w, "  Content inspected  %d\n", inv.Summary.ContentInspected)
	fmt.Fprintf(w, "  Files w/ indicators %d\n", inv.Summary.FilesWithSecretIndicators)
	fmt.Fprintf(w, "  Secret indicators   %d\n", inv.Summary.SecretIndicators)
	fmt.Fprintf(w, "  Broad+secret files  %d\n", inv.Summary.BroadlyAccessibleWithSecret)
	fmt.Fprintf(w, "  Inspection state    %s\n", inv.PlaintextRisk.InspectionState)
	fmt.Fprintf(w, "  Key posture state   %s\n", inv.PrivateKeyPermissions.AssessmentState)
	fmt.Fprintf(w, "  Key read exposed    %d\n", inv.PrivateKeyPermissions.ReadExposed)
	fmt.Fprintf(w, "  Key write exposed   %d\n", inv.PrivateKeyPermissions.WriteExposed)
	fmt.Fprintf(w, "  Key owner mismatch  %d\n", inv.PrivateKeyPermissions.SystemOwnerUnexpected)
	fmt.Fprintf(w, "  Credential posture  %s\n", inv.CredentialFilePosture.AssessmentState)
	fmt.Fprintf(w, "  Credential files    %d\n", inv.CredentialFilePosture.Files)
	fmt.Fprintf(w, "  Credential read exp %d\n", inv.CredentialFilePosture.ReadExposed)
	fmt.Fprintf(w, "  Credential write exp %d\n", inv.CredentialFilePosture.WriteExposed)

	if len(inv.Records) > 0 {
		fmt.Fprintln(w, "\nSECRET-BEARING PATH METADATA")
		limit := len(inv.Records)
		if !verbose && limit > 80 {
			limit = 80
		}
		for _, r := range inv.Records[:limit] {
			fmt.Fprintf(w, "  %-22s %-8s %-10s %s\n", r.Kind, r.Scope, r.PermissionState, r.Path)
			if verbose {
				fmt.Fprintf(w, "    state=%s directory=%t symlink=%t size=%d mode=%s owner=%s group=%s\n", r.State, r.Directory, r.Symlink, r.SizeBytes, value(r.Mode), value(r.OwnerID), value(r.GroupID))
				fmt.Fprintf(w, "    access: world-r=%s group-r=%s world-w=%s group-w=%s broad-r=%s broad-w=%s\n", r.WorldReadable, r.GroupReadable, r.WorldWritable, r.GroupWritable, r.BroadlyAccessible, r.BroadlyWritable)
				fmt.Fprintf(w, "    content: inspected=%t state=%s bytes=%d truncated=%t indicators=%d redacted=%t\n", r.ContentInspected, r.ContentInspectionState, r.ContentBytesInspected, r.ContentTruncated, r.SecretIndicatorCount, r.RedactionApplied)
				for _, ind := range r.SecretIndicators {
					fmt.Fprintf(w, "      - %s at line %d (value redacted)\n", ind.Type, ind.Line)
				}
				fmt.Fprintf(w, "    source=%s\n", r.CollectionSource)
				if r.Reason != "" {
					fmt.Fprintf(w, "    reason: %s\n", r.Reason)
				}
				if r.ContentReason != "" {
					fmt.Fprintf(w, "    content-reason: %s\n", r.ContentReason)
				}
			}
		}
		if limit < len(inv.Records) {
			fmt.Fprintf(w, "  ... %d additional record(s); use --verbose or --json\n", len(inv.Records)-limit)
		}
	}
	if verbose && len(inv.PrivateKeyPermissions.Records) > 0 {
		fmt.Fprintln(w, "\nPRIVATE-KEY PERMISSION POSTURE")
		for _, p := range inv.PrivateKeyPermissions.Records {
			fmt.Fprintf(w, "  %-8s read=%-10s write=%-10s owner=%-14s %s\n", p.Scope, p.ReadPosture, p.WritePosture, p.OwnerPosture, p.Path)
			if p.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", p.Reason)
			}
		}
	}
	if verbose && len(inv.CredentialFilePosture.Records) > 0 {
		fmt.Fprintln(w, "\nCLOUD / DEVELOPER CREDENTIAL-FILE POSTURE")
		for _, p := range inv.CredentialFilePosture.Records {
			fmt.Fprintf(w, "  %-12s %-14s read=%-14s write=%-10s %s\n", p.Provider, p.Role, p.ReadPosture, p.WritePosture, p.Path)
			if p.Reason != "" {
				fmt.Fprintf(w, "    reason: %s\n", p.Reason)
			}
		}
	}
	if verbose && len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nLIMITATIONS")
		for _, d := range inv.Degraded {
			fmt.Fprintf(w, "  - %s\n", d)
		}
	}
}
