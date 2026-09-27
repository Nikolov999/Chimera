package render

import (
	"fmt"
	"io"
	"strings"

	stginv "github.com/Nikolov999/chimera/internal/storage"
)

func StorageHuman(w io.Writer, inv stginv.Inventory, verbose bool) {
	fmt.Fprintln(w, "STORAGE & MEMORY-STATE PROTECTION")
	fmt.Fprintf(w, "  Platform            %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Volumes             %d (system=%d removable=%d)\n", inv.Summary.Volumes, inv.Summary.SystemVolumes, inv.Summary.RemovableVolumes)
	fmt.Fprintf(w, "  Encryption          encrypted=%d unencrypted=%d partial=%d unknown=%d\n", inv.Summary.EncryptedVolumes, inv.Summary.UnencryptedVolumes, inv.Summary.PartialVolumes, inv.Summary.UnknownVolumes)
	fmt.Fprintf(w, "  Protection          enabled=%d disabled=%d suspended=%d\n", inv.Summary.ProtectionEnabled, inv.Summary.ProtectionDisabled, inv.Summary.ProtectionSuspended)
	fmt.Fprintf(w, "  Swap/pagefile       areas=%d encrypted=%d unencrypted=%d unknown=%d volatile=%d\n", inv.Summary.SwapAreas, inv.Summary.EncryptedSwapAreas, inv.Summary.UnencryptedSwapAreas, inv.Summary.UnknownSwapAreas, inv.Summary.VolatileSwapAreas)
	fmt.Fprintf(w, "  Hibernation         %s exposure=%s\n", inv.Summary.HibernationConfiguration, inv.Summary.HibernationExposure)
	if inv.Summary.UnavailableMetadata > 0 {
		fmt.Fprintf(w, "  Limited metadata    %d\n", inv.Summary.UnavailableMetadata)
	}

	fmt.Fprintln(w, "\nVOLUMES")
	if len(inv.Volumes) == 0 {
		fmt.Fprintln(w, "  No security-relevant local storage volumes were returned by the platform provider.")
	}
	for _, v := range inv.Volumes {
		where := v.MountPoint
		if strings.TrimSpace(where) == "" {
			where = v.Device
		}
		role := "DATA"
		if v.SystemVolume {
			role = "SYSTEM"
		} else if v.Removable {
			role = "REMOVABLE"
		}
		fmt.Fprintf(w, "  %-10s %-12s %-11s %-18s %s\n", role, v.EncryptionState, v.ProtectionState, truncate(fallbackRender(v.EncryptionProduct, "-"), 18), truncate(where, 78))
		if verbose {
			fmt.Fprintf(w, "    id:            %s\n", v.ID)
			fmt.Fprintf(w, "    device/fs:     %s / %s\n", fallbackRender(v.Device, "-"), fallbackRender(v.Filesystem, "-"))
			fmt.Fprintf(w, "    lock:          %s\n", v.LockState)
			if v.EncryptionPercentage != nil {
				fmt.Fprintf(w, "    encrypted:     %.1f%%\n", *v.EncryptionPercentage)
			}
			if v.EncryptionMethod != "" {
				fmt.Fprintf(w, "    method:        %s\n", truncate(v.EncryptionMethod, 120))
			}
			if v.AutoUnlock != "" {
				fmt.Fprintf(w, "    auto-unlock:   %s\n", v.AutoUnlock)
			}
			if v.VolumeName != "" {
				fmt.Fprintf(w, "    volume:        %s\n", truncate(v.VolumeName, 120))
			}
			if v.MajorMinor != "" {
				fmt.Fprintf(w, "    major:minor:   %s\n", v.MajorMinor)
			}
			if v.Reason != "" {
				fmt.Fprintf(w, "    note:          %s\n", truncate(v.Reason, 160))
			}
			fmt.Fprintf(w, "    source:        %s\n", truncate(v.CollectionSource, 140))
		}
	}

	fmt.Fprintln(w, "\nSWAP / PAGEFILE")
	if len(inv.SwapAreas) == 0 {
		fmt.Fprintln(w, "  No active swap/pagefile areas were returned by the platform provider.")
	}
	for _, s := range inv.SwapAreas {
		fmt.Fprintf(w, "  %-12s %-13s %-12s %s\n", s.Kind, s.EncryptionState, humanBytes(s.SizeBytes), truncate(s.Path, 90))
		if verbose {
			fmt.Fprintf(w, "    id:            %s\n", s.ID)
			fmt.Fprintf(w, "    used:          %s\n", humanBytes(s.UsedBytes))
			if s.EncryptionProduct != "" {
				fmt.Fprintf(w, "    protection:    %s\n", truncate(s.EncryptionProduct, 120))
			}
			if s.EncryptionBasis != "" {
				fmt.Fprintf(w, "    basis:         %s\n", truncate(s.EncryptionBasis, 160))
			}
			if s.Reason != "" {
				fmt.Fprintf(w, "    note:          %s\n", truncate(s.Reason, 160))
			}
			fmt.Fprintf(w, "    source:        %s\n", truncate(s.CollectionSource, 140))
		}
	}

	h := inv.Hibernation
	fmt.Fprintln(w, "\nHIBERNATION / PERSISTENT SLEEP")
	fmt.Fprintf(w, "  Configuration       %s\n", h.ConfigurationState)
	fmt.Fprintf(w, "  Support             %s\n", h.SupportState)
	fmt.Fprintf(w, "  Exposure            %s\n", h.ExposureState)
	fmt.Fprintf(w, "  Image encryption    %s\n", h.EncryptionState)
	if h.Mode != "" {
		fmt.Fprintf(w, "  Mode                %s\n", truncate(h.Mode, 120))
	}
	if h.ImagePath != "" {
		fmt.Fprintf(w, "  Image path          %s\n", truncate(h.ImagePath, 120))
	}
	if h.ResumeTarget != "" {
		fmt.Fprintf(w, "  Resume target       %s\n", truncate(h.ResumeTarget, 120))
	}
	if verbose {
		if h.FastStartupState != "" && h.FastStartupState != "UNKNOWN" {
			fmt.Fprintf(w, "  Fast startup        %s\n", h.FastStartupState)
		}
		if h.DestroyFileVaultKeyOnStandby != "" && h.DestroyFileVaultKeyOnStandby != "UNKNOWN" {
			fmt.Fprintf(w, "  Destroy FV key      %s\n", h.DestroyFileVaultKeyOnStandby)
		}
		if h.ProtectionBasis != "" {
			fmt.Fprintf(w, "  Protection basis    %s\n", truncate(h.ProtectionBasis, 160))
		}
		if h.Reason != "" {
			fmt.Fprintf(w, "  Note                %s\n", truncate(h.Reason, 180))
		}
		fmt.Fprintf(w, "  Source              %s\n", truncate(h.CollectionSource, 140))
	}

	if verbose && len(inv.Sources) > 0 {
		fmt.Fprintln(w, "\nPROVIDERS")
		for _, src := range inv.Sources {
			fmt.Fprintf(w, "  %-12s %-24s items=%d %s\n", src.State, src.ID, src.ItemCount, truncate(src.Source, 100))
			if src.Reason != "" {
				fmt.Fprintf(w, "    note: %s\n", truncate(src.Reason, 160))
			}
		}
	}
	if len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nLIMITATIONS")
		for _, d := range inv.Degraded {
			fmt.Fprintf(w, "  - %s\n", truncate(d, 180))
		}
	}
}

func humanBytes(v uint64) string {
	const unit = 1024
	if v < unit {
		return fmt.Sprintf("%dB", v)
	}
	div, exp := uint64(unit), 0
	for n := v / unit; n >= unit && exp < 5; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(v)/float64(div), "KMGTPE"[exp])
}
