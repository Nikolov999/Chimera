package render

import (
	"fmt"
	"io"
	"strings"

	fsinv "github.com/Nikolov999/chimera/internal/filesystem"
)

func FilesystemHuman(w io.Writer, inv fsinv.Inventory, verbose bool) {
	fmt.Fprintln(w, "FILESYSTEM SECURITY INVENTORY")
	fmt.Fprintf(w, "  Platform            %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Permission model    %s (%s)\n", inv.PermissionCapability.Model, inv.PermissionCapability.State)
	fmt.Fprintf(w, "  Paths               %d\n", inv.Summary.Paths)
	fmt.Fprintf(w, "  Security roots      %d\n", inv.Summary.SecurityRoots)
	fmt.Fprintf(w, "  Temp areas          %d\n", inv.Summary.TempAreas)
	fmt.Fprintf(w, "  Search paths        %d\n", inv.Summary.SearchPaths)
	fmt.Fprintf(w, "  Sensitive locations%d\n", inv.Summary.SensitiveLocations)
	fmt.Fprintf(w, "  Existing paths      %d\n", inv.Summary.ExistingPaths)
	fmt.Fprintf(w, "  Mount/volumes       %d (rw=%d ro=%d network=%d removable=%d encrypted=%d)\n", inv.Summary.MountBoundaries, inv.Summary.WritableMounts, inv.Summary.ReadOnlyMounts, inv.Summary.NetworkMounts, inv.Summary.RemovableMounts, inv.Summary.EncryptedMounts)
	fmt.Fprintf(w, "  Network shares      %d (mounted=%d exported=%d nfs=%d smb=%d broad=%d broad-write=%d dangerous=%d)\n", inv.Summary.NetworkShares, inv.Summary.MountedNetworkShares, inv.Summary.ExportedNetworkShares, inv.Summary.NFSNetworkShares, inv.Summary.SMBNetworkShares, inv.Summary.BroadNetworkShares, inv.Summary.BroadWritableNetworkShares, inv.Summary.DangerousNetworkShares)
	fmt.Fprintf(w, "  Executable dirs     %d\n", inv.Summary.ExecutableDirectories)
	fmt.Fprintf(w, "  Executables         %d\n", inv.Summary.Executables)
	fmt.Fprintf(w, "  Broad writable      %d (%d confirmed untrusted)\n", inv.Summary.BroadlyWritableExecutables, inv.Summary.UntrustedWritableExecutables)
	fmt.Fprintf(w, "  Priv search paths   %d (%d broad-write / %d lower-priv control)\n", inv.Summary.PrivilegedSearchPaths, inv.Summary.WritablePrivilegedSearchPaths, inv.Summary.UntrustedPrivilegedSearchPaths)
	fmt.Fprintf(w, "  Loader search paths %d (%d weak)\n", inv.Summary.LoaderSearchPaths, inv.Summary.WritableLoaderSearchPaths)
	fmt.Fprintf(w, "  Privileged execs    %d (setuid=%d setgid=%d filecap=%d review=%d)\n", inv.Summary.PrivilegedFiles, inv.Summary.SetUIDFiles, inv.Summary.SetGIDFiles, inv.Summary.CapabilityFiles, inv.Summary.CustomPrivilegedFiles)
	fmt.Fprintf(w, "  Sensitive paths    %d (broad-write=%d untrusted-write=%d broad-access=%d owner-mismatch=%d)\n", inv.Summary.SensitiveFiles, inv.Summary.SensitiveBroadlyWritable, inv.Summary.SensitiveUntrustedWritable, inv.Summary.SensitiveBroadlyAccessible, inv.Summary.SensitiveOwnerMismatches)
	fmt.Fprintf(w, "  ACL boundaries     %d (extended=%d dangerous=%d review=%d unresolved=%d)\n", inv.Summary.ACLBoundaries, inv.Summary.ExtendedACLBoundaries, inv.Summary.DangerousACLBoundaries, inv.Summary.ReviewACLBoundaries, inv.Summary.UnavailableACLMetadata)
	fmt.Fprintf(w, "  Temp security      %d (shared=%d unsafe=%d owner=%d perms=%d parent=%d unresolved=%d)\n", inv.Summary.TempDirectories, inv.Summary.SharedTempDirectories, inv.Summary.UnsafeTempDirectories, inv.Summary.UnsafeTempOwnership, inv.Summary.UnsafeTempPermissions, inv.Summary.UnsafeTempParentBoundaries, inv.Summary.UnavailableTempMetadata)
	if inv.Summary.UnavailableExecutableMetadata > 0 {
		fmt.Fprintf(w, "  Executable unknown  %d\n", inv.Summary.UnavailableExecutableMetadata)
	}
	if inv.Summary.DeniedPaths > 0 || inv.Summary.UnavailablePaths > 0 {
		fmt.Fprintf(w, "  Limited paths       denied=%d unavailable=%d\n", inv.Summary.DeniedPaths, inv.Summary.UnavailablePaths)
	}

	fmt.Fprintln(w, "\nSECURITY-RELEVANT PATHS")
	if len(inv.Paths) == 0 {
		fmt.Fprintln(w, "  No path records were returned.")
	}
	for _, p := range inv.Paths {
		status := string(p.State)
		if p.State == "OBSERVED" && !p.Exists {
			status = "ABSENT"
		}
		fmt.Fprintf(w, "  %-16s %-11s %s\n", truncate(p.Kind, 16), status, truncate(p.Path, 96))
		if verbose {
			fmt.Fprintf(w, "    id:           %s\n", p.ID)
			fmt.Fprintf(w, "    permissions:  model=%s mode=%s owner=%s group=%s\n", p.PermissionModel, fallbackRender(p.Mode, "-"), fallbackRender(p.OwnerID, "-"), fallbackRender(p.GroupID, "-"))
			if p.MountPoint != "" {
				fmt.Fprintf(w, "    mount:        %s\n", truncate(p.MountPoint, 96))
			}
			if p.Reason != "" {
				fmt.Fprintf(w, "    note:         %s\n", truncate(p.Reason, 150))
			}
			fmt.Fprintf(w, "    source:       %s\n", truncate(p.CollectionSource, 120))
		}
	}

	fmt.Fprintln(w, "\nBROADLY WRITABLE EXECUTABLES")
	risky := 0
	for _, x := range inv.Executables {
		if !x.BroadlyWritable && !x.UntrustedWrite {
			continue
		}
		risky++
		classification := "BROAD_WRITE"
		if x.UntrustedWrite {
			classification = "UNTRUSTED_WRITE"
		}
		fmt.Fprintf(w, "  %-16s %s\n", classification, truncate(x.Path, 100))
		if verbose {
			fmt.Fprintf(w, "    id:           %s\n", x.ID)
			fmt.Fprintf(w, "    permissions:  model=%s mode=%s owner=%s group=%s\n", x.PermissionModel, fallbackRender(x.Mode, "-"), fallbackRender(x.OwnerID, "-"), fallbackRender(x.GroupID, "-"))
			if len(x.WritePrincipals) > 0 {
				fmt.Fprintf(w, "    writers:      %s\n", truncate(strings.Join(x.WritePrincipals, ", "), 150))
			}
			if x.ResolvedPath != "" {
				fmt.Fprintf(w, "    resolved:     %s\n", truncate(x.ResolvedPath, 120))
			}
			if x.Reason != "" {
				fmt.Fprintf(w, "    note:         %s\n", truncate(x.Reason, 150))
			}
			fmt.Fprintf(w, "    source:       %s\n", truncate(x.CollectionSource, 120))
		}
	}
	if risky == 0 {
		fmt.Fprintln(w, "  No broadly writable executable was observed in the bounded executable search inventory.")
	}

	fmt.Fprintln(w, "\nSENSITIVE FILE PERMISSIONS")
	displayedSensitive := 0
	for _, sf := range inv.SensitiveFiles {
		risky := sf.UntrustedWrite || sf.BroadlyWritable || sf.UntrustedAccess || (sf.AccessPolicy == fsinv.SensitivePolicyOwnerOnly && sf.BroadlyAccessible) || sf.OwnerState == fsinv.SensitiveOwnerUnexpected
		if !verbose && !risky {
			continue
		}
		displayedSensitive++
		status := string(sf.State)
		if sf.State == "OBSERVED" && !sf.Exists {
			status = "ABSENT"
		} else if risky {
			status = "REVIEW"
		}
		fmt.Fprintf(w, "  %-10s %-22s %-15s %s\n", status, truncate(sf.Kind, 22), truncate(sf.AccessPolicy, 15), truncate(sf.Path, 82))
		if verbose {
			fmt.Fprintf(w, "    id:           %s\n", sf.ID)
			fmt.Fprintf(w, "    scope/owner:  %s owner=%s expected=%s state=%s\n", sf.Scope, fallbackRender(sf.OwnerID, "-"), fallbackRender(sf.ExpectedOwnerID, "-"), sf.OwnerState)
			fmt.Fprintf(w, "    permissions:  model=%s mode=%s broad-write=%t broad-access=%t\n", sf.PermissionModel, fallbackRender(sf.Mode, "-"), sf.BroadlyWritable, sf.BroadlyAccessible)
			if len(sf.WritePrincipals) > 0 {
				fmt.Fprintf(w, "    writers:      %s\n", truncate(strings.Join(sf.WritePrincipals, ", "), 150))
			}
			if len(sf.ReadPrincipals) > 0 {
				fmt.Fprintf(w, "    readers:      %s\n", truncate(strings.Join(sf.ReadPrincipals, ", "), 150))
			}
			if sf.ResolvedPath != "" {
				fmt.Fprintf(w, "    resolved:     %s\n", truncate(sf.ResolvedPath, 120))
			}
			if sf.Reason != "" {
				fmt.Fprintf(w, "    note:         %s\n", truncate(sf.Reason, 150))
			}
			fmt.Fprintf(w, "    source:       %s\n", truncate(sf.CollectionSource, 120))
		}
	}
	if len(inv.SensitiveFiles) == 0 {
		fmt.Fprintln(w, "  No sensitive-path permission records were returned by the platform provider.")
	} else if displayedSensitive == 0 && !verbose {
		fmt.Fprintln(w, "  No sensitive-path permission or ownership violation was observed.")
	}

	fmt.Fprintln(w, "\nNATIVE ACL BOUNDARIES")
	displayedACL := 0
	const maxDisplayedACL = 200
	for _, acl := range inv.ACLBoundaries {
		risky := acl.DangerousBroadWrite || acl.DangerousBroadControl || acl.ReviewWriteGrant || acl.State != "OBSERVED"
		if !verbose && !risky {
			continue
		}
		if displayedACL >= maxDisplayedACL {
			break
		}
		displayedACL++
		status := string(acl.State)
		if acl.State == "OBSERVED" && !acl.Exists {
			status = "ABSENT"
		} else if acl.DangerousBroadWrite || acl.DangerousBroadControl {
			status = "WEAK"
		} else if acl.ReviewWriteGrant {
			status = "REVIEW"
		}
		fmt.Fprintf(w, "  %-11s %-30s %s\n", status, truncate(strings.Join(acl.Contexts, ","), 30), truncate(acl.Path, 86))
		if verbose {
			fmt.Fprintf(w, "    id/model:      %s %s owner=%s extended=%t\n", acl.ID, acl.ACLModel, fallbackRender(acl.OwnerID, "-"), acl.HasExtendedACL)
			if len(acl.DangerousPrincipals) > 0 {
				fmt.Fprintf(w, "    broad control: %s\n", truncate(strings.Join(acl.DangerousPrincipals, ", "), 160))
			}
			if len(acl.ReviewPrincipals) > 0 {
				fmt.Fprintf(w, "    named writers: %s\n", truncate(strings.Join(acl.ReviewPrincipals, ", "), 160))
			}
			for _, g := range acl.Grants {
				if !g.WriteLike && !g.ControlLike {
					continue
				}
				fmt.Fprintf(w, "    grant:         %s %s rights=%s inherited=%t broad=%t trusted=%t effective=%t\n", truncate(g.Access, 8), truncate(g.Principal, 42), truncate(strings.Join(g.Rights, ","), 90), g.Inherited, g.Broad, g.Trusted, g.Effective)
			}
			if acl.Reason != "" {
				fmt.Fprintf(w, "    note:          %s\n", truncate(acl.Reason, 160))
			}
			fmt.Fprintf(w, "    source:        %s\n", truncate(acl.CollectionSource, 120))
		}
	}
	if len(inv.ACLBoundaries) == 0 {
		fmt.Fprintln(w, "  No selected ACL boundary records were returned by the platform provider.")
	} else if displayedACL == 0 && !verbose {
		fmt.Fprintln(w, "  No dangerous broad or unexpected named write ACL grant was observed on selected high-impact paths.")
	}
	if displayedACL >= maxDisplayedACL && len(inv.ACLBoundaries) > displayedACL {
		fmt.Fprintf(w, "  ... output capped at %d ACL boundary records; use --json for the complete normalized inventory.\n", maxDisplayedACL)
	}

	fmt.Fprintln(w, "\nTEMPORARY DIRECTORY SECURITY")
	displayedTemp := 0
	for _, td := range inv.TempDirectories {
		risky := td.UnsafeOwnership || td.UnsafePermissions || td.ParentUnsafe || td.State != "OBSERVED" || (td.ParentState != "" && td.ParentState != "OBSERVED")
		if !verbose && !risky {
			continue
		}
		displayedTemp++
		status := string(td.State)
		if td.State == "OBSERVED" && !td.Exists {
			status = "ABSENT"
		} else if td.UnsafeOwnership || td.UnsafePermissions || td.ParentUnsafe {
			status = "WEAK"
		}
		fmt.Fprintf(w, "  %-11s %-20s %s\n", status, truncate(td.Scope, 20), truncate(td.Path, 96))
		if verbose {
			fmt.Fprintf(w, "    id:           %s\n", td.ID)
			fmt.Fprintf(w, "    permissions:  model=%s mode=%s owner=%s group=%s sticky=%t shared=%t\n", td.PermissionModel, fallbackRender(td.Mode, "-"), fallbackRender(td.OwnerID, "-"), fallbackRender(td.GroupID, "-"), td.StickyBit, td.Shared)
			fmt.Fprintf(w, "    posture:      broad-create=%t broad-control=%t unsafe-owner=%t unsafe-perms=%t parent-unsafe=%t\n", td.BroadCreate, td.BroadControl, td.UnsafeOwnership, td.UnsafePermissions, td.ParentUnsafe)
			if len(td.WritePrincipals) > 0 {
				fmt.Fprintf(w, "    writers:      %s\n", truncate(strings.Join(td.WritePrincipals, ", "), 150))
			}
			if td.ParentPath != "" {
				fmt.Fprintf(w, "    parent:       %s state=%s mode=%s owner=%s sticky=%t broad-write=%t\n", truncate(td.ParentPath, 96), fallbackRender(string(td.ParentState), "-"), fallbackRender(td.ParentMode, "-"), fallbackRender(td.ParentOwnerID, "-"), td.ParentStickyBit, td.ParentBroadlyWritable)
			}
			if td.ResolvedPath != "" {
				fmt.Fprintf(w, "    resolved:     %s\n", truncate(td.ResolvedPath, 120))
			}
			if td.Reason != "" {
				fmt.Fprintf(w, "    note:         %s\n", truncate(td.Reason, 150))
			}
			fmt.Fprintf(w, "    source:       %s\n", truncate(td.CollectionSource, 120))
		}
	}
	if len(inv.TempDirectories) == 0 {
		fmt.Fprintln(w, "  No temporary-directory security records were returned by the platform provider.")
	} else if displayedTemp == 0 && !verbose {
		fmt.Fprintln(w, "  No unsafe temporary-directory ownership, permission, or parent boundary was observed.")
	}

	fmt.Fprintln(w, "\nPRIVILEGED SEARCH PATHS")
	weakSearch := 0
	for _, sp := range inv.SearchPaths {
		if !sp.UntrustedWrite && sp.State == "OBSERVED" && sp.Exists && sp.Directory {
			if !verbose {
				continue
			}
		}
		if sp.UntrustedWrite {
			weakSearch++
		}
		status := string(sp.State)
		if sp.State == "OBSERVED" && !sp.Exists {
			status = "ABSENT"
		}
		if sp.UntrustedWrite {
			status = "WEAK"
		}
		fmt.Fprintf(w, "  %-12s %-28s %s\n", status, truncate(strings.Join(sp.Contexts, ","), 28), truncate(sp.Path, 92))
		if verbose {
			fmt.Fprintf(w, "    id:           %s\n", sp.ID)
			fmt.Fprintf(w, "    permissions:  model=%s mode=%s owner=%s group=%s\n", sp.PermissionModel, fallbackRender(sp.Mode, "-"), fallbackRender(sp.OwnerID, "-"), fallbackRender(sp.GroupID, "-"))
			if len(sp.WritePrincipals) > 0 {
				fmt.Fprintf(w, "    writers:      %s\n", truncate(strings.Join(sp.WritePrincipals, ", "), 150))
			}
			if sp.ResolvedPath != "" {
				fmt.Fprintf(w, "    resolved:     %s\n", truncate(sp.ResolvedPath, 120))
			}
			if sp.Reason != "" {
				fmt.Fprintf(w, "    note:         %s\n", truncate(sp.Reason, 150))
			}
			fmt.Fprintf(w, "    source:       %s\n", truncate(strings.Join(sp.DiscoverySources, "; "), 150))
		}
	}
	if len(inv.SearchPaths) == 0 {
		fmt.Fprintln(w, "  No privileged search-path records were returned by the platform provider.")
	} else if weakSearch == 0 && !verbose {
		fmt.Fprintln(w, "  No lower-privilege-controlled privileged search directory was observed.")
	}

	fmt.Fprintln(w, "\nLINUX PRIVILEGED EXECUTABLES")
	displayedPrivileged := 0
	const maxDisplayedPrivileged = 200
	for _, pf := range inv.PrivilegedFiles {
		if !verbose && !pf.ReviewRequired {
			continue
		}
		if displayedPrivileged >= maxDisplayedPrivileged {
			break
		}
		displayedPrivileged++
		flags := []string{}
		if pf.SetUID {
			flags = append(flags, "SETUID")
		}
		if pf.SetGID {
			flags = append(flags, "SETGID")
		}
		if len(pf.Capabilities) > 0 || len(pf.InheritableCaps) > 0 {
			flags = append(flags, "FILECAP")
		}
		status := pf.Classification
		if pf.ReviewRequired {
			status = "REVIEW"
		}
		fmt.Fprintf(w, "  %-11s %-22s %s\n", truncate(status, 11), truncate(strings.Join(flags, ","), 22), truncate(pf.Path, 88))
		if verbose {
			fmt.Fprintf(w, "    id:           %s\n", pf.ID)
			fmt.Fprintf(w, "    mode/owner:   %s uid=%s gid=%s\n", fallbackRender(pf.Mode, "-"), fallbackRender(pf.OwnerID, "-"), fallbackRender(pf.GroupID, "-"))
			if len(pf.Capabilities) > 0 {
				fmt.Fprintf(w, "    capabilities: %s effective=%t\n", truncate(strings.Join(pf.Capabilities, ", "), 150), pf.CapabilityEffective)
			}
			if len(pf.InheritableCaps) > 0 {
				fmt.Fprintf(w, "    inheritable:  %s\n", truncate(strings.Join(pf.InheritableCaps, ", "), 150))
			}
			fmt.Fprintf(w, "    package:      %s provider=%s id=%s\n", pf.PackageOwnership, fallbackRender(pf.PackageProvider, "-"), fallbackRender(pf.PackageID, "-"))
			if len(pf.ReviewReasons) > 0 {
				fmt.Fprintf(w, "    review:       %s\n", truncate(strings.Join(pf.ReviewReasons, "; "), 180))
			}
			if pf.Reason != "" {
				fmt.Fprintf(w, "    note:         %s\n", truncate(pf.Reason, 180))
			}
		}
	}
	if len(inv.PrivilegedFiles) == 0 {
		applicable := true
		for _, src := range inv.Sources {
			if src.ID == "linux-privileged-files" && string(src.State) == "NOT_APPLICABLE" {
				applicable = false
				break
			}
		}
		if applicable {
			fmt.Fprintln(w, "  No SUID/SGID/file-capability executable was observed by the Linux provider.")
		} else {
			fmt.Fprintln(w, "  Not applicable on this platform.")
		}
	} else if displayedPrivileged == 0 && !verbose {
		fmt.Fprintln(w, "  No custom or unexpected Linux privileged executable requires review.")
	}
	if displayedPrivileged >= maxDisplayedPrivileged && len(inv.PrivilegedFiles) > displayedPrivileged {
		fmt.Fprintf(w, "  ... output capped at %d privileged executable records; use --json for the complete normalized inventory.\n", maxDisplayedPrivileged)
	}

	fmt.Fprintln(w, "\nNETWORK SHARE SECURITY")
	if len(inv.NetworkShares) == 0 {
		fmt.Fprintln(w, "  No mounted network share or local NFS export was observed by the providers.")
	}
	const maxDisplayedNetworkShares = 200
	displayedNetworkShares := 0
	for _, sh := range inv.NetworkShares {
		if displayedNetworkShares >= maxDisplayedNetworkShares {
			break
		}
		displayedNetworkShares++
		status := string(sh.State)
		if sh.GuestAllowed || sh.AnonymousAllowed || sh.BroadWrite || len(sh.DangerousOptions) > 0 {
			status = "WEAK"
		} else if sh.BroadAccess {
			status = "REVIEW"
		}
		access := sh.AccessMode
		if access == "" {
			access = "UNKNOWN"
		}
		endpoint := sh.LocalPath
		if sh.Remote != "" {
			endpoint += " -> " + sh.Remote
		}
		fmt.Fprintf(w, "  %-10s %-8s %-9s %-12s %s\n", truncate(status, 10), truncate(sh.Direction, 8), truncate(sh.Protocol, 9), truncate(access, 12), truncate(endpoint, 78))
		if verbose {
			fmt.Fprintf(w, "    id/name:      %s / %s\n", sh.ID, fallbackRender(sh.Name, "-"))
			fmt.Fprintf(w, "    exposure:     guest=%t anonymous=%t broad=%t broad-write=%t\n", sh.GuestAllowed, sh.AnonymousAllowed, sh.BroadAccess, sh.BroadWrite)
			if len(sh.SecurityOptions) > 0 {
				fmt.Fprintf(w, "    security:     %s\n", truncate(strings.Join(sh.SecurityOptions, ", "), 160))
			}
			if len(sh.DangerousOptions) > 0 {
				fmt.Fprintf(w, "    weak options: %s\n", truncate(strings.Join(sh.DangerousOptions, ", "), 160))
			}
			if sh.Reason != "" {
				fmt.Fprintf(w, "    note:         %s\n", truncate(sh.Reason, 160))
			}
			fmt.Fprintf(w, "    source:       %s confidence=%s\n", truncate(sh.CollectionSource, 120), sh.Confidence)
		}
	}
	if displayedNetworkShares >= maxDisplayedNetworkShares && len(inv.NetworkShares) > displayedNetworkShares {
		fmt.Fprintf(w, "  ... output capped at %d network-share records; use --json for the complete normalized inventory.\n", maxDisplayedNetworkShares)
	}

	fmt.Fprintln(w, "\nMOUNT / VOLUME INVENTORY")
	if len(inv.MountBoundaries) == 0 {
		fmt.Fprintln(w, "  No mount/volume records were returned by the platform provider.")
	}
	for _, m := range inv.MountBoundaries {
		flags := []string{m.AccessMode, m.Classification}
		if m.Filesystem != "" {
			flags = append(flags, m.Filesystem)
		}
		if m.EncryptionState == fsinv.MountEncryptionEncrypted {
			flags = append(flags, "ENCRYPTED")
		}
		fmt.Fprintf(w, "  %-11s %-42s %s\n", m.State, truncate(strings.Join(flags, ","), 42), truncate(m.Path, 74))
		if verbose {
			if m.BackingSource != "" {
				fmt.Fprintf(w, "    backing:      %s\n", truncate(m.BackingSource, 120))
			}
			fmt.Fprintf(w, "    access/class: %s class=%s network=%t removable=%t\n", m.AccessMode, m.Classification, m.Network, m.Removable)
			fmt.Fprintf(w, "    encryption:   %s type=%s\n", m.EncryptionState, fallbackRender(m.EncryptionType, "-"))
			if m.EncryptionEvidence != "" {
				fmt.Fprintf(w, "    enc evidence: %s\n", truncate(m.EncryptionEvidence, 150))
			}
			if m.VolumeLabel != "" {
				fmt.Fprintf(w, "    volume label: %s\n", truncate(m.VolumeLabel, 120))
			}
			if m.MajorMinor != "" {
				fmt.Fprintf(w, "    major:minor:  %s\n", m.MajorMinor)
			}
			if len(m.Options) > 0 {
				fmt.Fprintf(w, "    options:      %s\n", truncate(strings.Join(m.Options, ","), 160))
			}
			if m.Reason != "" {
				fmt.Fprintf(w, "    note:         %s\n", truncate(m.Reason, 150))
			}
			fmt.Fprintf(w, "    source:       %s\n", truncate(m.CollectionSource, 120))
		}
	}

	if verbose && len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nDEGRADED EVIDENCE")
		for _, d := range inv.Degraded {
			fmt.Fprintf(w, "  - %s\n", d)
		}
	}
}
