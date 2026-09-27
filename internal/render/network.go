package render

import (
	"fmt"
	"io"
	"strings"

	netinv "github.com/Nikolov999/chimera/internal/network"
)

func NetworkHuman(w io.Writer, inv netinv.Inventory, verbose bool) {
	fmt.Fprintln(w, "NETWORK EXPOSURE")
	fmt.Fprintf(w, "  Schema             %s\n", inv.Schema)
	fmt.Fprintf(w, "  Collector          %s\n", inv.CollectorVersion)
	fmt.Fprintf(w, "  Platform           %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Collected          %s\n", inv.CollectedAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Endpoints          %d\n", inv.Summary.Endpoints)
	fmt.Fprintf(w, "  TCP listeners      %d\n", inv.Summary.TCPListeners)
	fmt.Fprintf(w, "  UDP bound          %d\n", inv.Summary.UDPBound)
	fmt.Fprintf(w, "  IPv4               %d\n", inv.Summary.IPv4)
	fmt.Fprintf(w, "  IPv6               %d\n", inv.Summary.IPv6)
	fmt.Fprintf(w, "  All interfaces     %d\n", inv.Summary.AllInterfaces)
	fmt.Fprintf(w, "  Loopback only      %d\n", inv.Summary.LoopbackOnly)
	fmt.Fprintf(w, "  Non-loopback       %d\n", inv.Summary.NonLoopback)
	fmt.Fprintf(w, "  Process owner      %d\n", inv.Summary.OwnedByProcess)
	fmt.Fprintf(w, "  Service owner      %d\n", inv.Summary.OwnedByService)
	fmt.Fprintf(w, "  Owner unavailable  %d\n", inv.Summary.OwnerUnavailable)

	fmt.Fprintln(w, "\nPROVIDERS")
	if len(inv.Sources) == 0 {
		fmt.Fprintln(w, "  No local socket provider status returned.")
	}
	for _, src := range inv.Sources {
		fmt.Fprintf(w, "  %-24s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
		if verbose && src.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", src.Reason)
		}
	}

	fmt.Fprintln(w, "\nENDPOINTS")
	if len(inv.Endpoints) == 0 {
		fmt.Fprintln(w, "  No listening/bound local TCP/UDP endpoints were returned by available providers.")
	}
	for _, e := range inv.Endpoints {
		owner := e.Owner.ProcessName
		if owner == "" && e.Owner.PID > 0 {
			owner = fmt.Sprintf("pid:%d", e.Owner.PID)
		}
		if owner == "" {
			owner = "UNAVAILABLE"
		}
		fmt.Fprintf(w, "  %-3s %-6s %-5s %-39s %-15s %s\n", e.Protocol, e.TransportState, e.AddressFamily, truncate(fmt.Sprintf("%s:%d", e.LocalAddress, e.LocalPort), 39), truncate(e.InterfaceBinding.Class, 15), truncate(owner, 40))
		if verbose {
			fmt.Fprintf(w, "    id:         %s\n", e.ID)
			fmt.Fprintf(w, "    binding:    %s", e.InterfaceBinding.Class)
			if len(e.InterfaceBinding.Interfaces) > 0 {
				fmt.Fprintf(w, " interfaces=%s", strings.Join(e.InterfaceBinding.Interfaces, ","))
			}
			fmt.Fprintln(w)
			fmt.Fprintf(w, "    owner:      state=%s pid=%d process=%s\n", e.Owner.State, e.Owner.PID, fallbackRender(e.Owner.ProcessName, "UNAVAILABLE"))
			if e.Owner.Executable != "" {
				fmt.Fprintf(w, "    executable: %s\n", truncate(e.Owner.Executable, 120))
			}
			if e.Owner.ServiceName != "" {
				fmt.Fprintf(w, "    service:    %s\n", e.Owner.ServiceName)
			}
			fmt.Fprintf(w, "    source:     %s\n", e.CollectionSource)
			fmt.Fprintf(w, "    confidence: %s\n", e.Confidence)
		}
	}
	if verbose && len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nDEGRADED EVIDENCE")
		for _, d := range inv.Degraded {
			fmt.Fprintln(w, "  - "+d)
		}
	}
}
func fallbackRender(v, f string) string {
	if strings.TrimSpace(v) == "" {
		return f
	}
	return strings.TrimSpace(v)
}
