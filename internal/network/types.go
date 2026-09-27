package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.network/v1"
	CollectorName    = "network-listeners"
	CollectorVersion = "network/phase052-v1"
	maxEndpoints     = 32768
)

type Owner struct {
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	Executable  string `json:"executable,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	State       string `json:"state"`
	Source      string `json:"source,omitempty"`
}

type Binding struct {
	Class      string   `json:"class"`
	Interfaces []string `json:"interfaces,omitempty"`
	IsWildcard bool     `json:"is_wildcard"`
	IsLoopback bool     `json:"is_loopback"`
}

type Endpoint struct {
	ID               string              `json:"id"`
	Protocol         string              `json:"protocol"`
	TransportState   string              `json:"transport_state"`
	AddressFamily    string              `json:"address_family"`
	LocalAddress     string              `json:"local_address"`
	LocalPort        uint16              `json:"local_port"`
	InterfaceBinding Binding             `json:"interface_binding"`
	Owner            Owner               `json:"owner"`
	SocketIdentity   string              `json:"socket_identity,omitempty"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

type SourceStatus struct {
	ID        string         `json:"id"`
	State     evidence.State `json:"state"`
	Source    string         `json:"source"`
	ItemCount int            `json:"item_count"`
	Reason    string         `json:"reason,omitempty"`
}

type Summary struct {
	Endpoints        int `json:"endpoints"`
	TCPListeners     int `json:"tcp_listeners"`
	UDPBound         int `json:"udp_bound"`
	IPv4             int `json:"ipv4"`
	IPv6             int `json:"ipv6"`
	AllInterfaces    int `json:"all_interfaces"`
	LoopbackOnly     int `json:"loopback_only"`
	NonLoopback      int `json:"non_loopback"`
	OwnedByProcess   int `json:"owned_by_process"`
	OwnedByService   int `json:"owned_by_service"`
	OwnerUnavailable int `json:"owner_unavailable"`
}

type Inventory struct {
	Schema           string                 `json:"schema"`
	EvidenceSchema   string                 `json:"evidence_schema"`
	Collector        string                 `json:"collector"`
	CollectorVersion string                 `json:"collector_version"`
	Platform         string                 `json:"platform"`
	Architecture     string                 `json:"architecture"`
	CollectedAt      time.Time              `json:"collected_at"`
	Endpoints        []Endpoint             `json:"endpoints"`
	Sources          []SourceStatus         `json:"sources"`
	Summary          Summary                `json:"summary"`
	Evidence         []evidence.Observation `json:"evidence"`
	Degraded         []string               `json:"degraded,omitempty"`
}

func Collect(ctx context.Context) Inventory {
	at := time.Now().UTC()
	inv := Inventory{Schema: SchemaVersion, EvidenceSchema: evidence.SchemaVersion, Collector: CollectorName, CollectorVersion: CollectorVersion, Platform: runtime.GOOS, Architecture: runtime.GOARCH, CollectedAt: at}
	collectPlatform(ctx, &inv)
	inv.Endpoints = normalizeEndpoints(inv.Endpoints)
	inv.Sources = normalizeSources(inv.Sources)
	inv.Degraded = uniqueSorted(inv.Degraded)
	inv.Summary = summarize(inv.Endpoints)
	inv.Evidence = buildEvidence(inv)
	return inv
}

func (inv Inventory) Validate() error {
	if inv.Schema != SchemaVersion || inv.EvidenceSchema != evidence.SchemaVersion || inv.Collector != CollectorName || inv.CollectorVersion != CollectorVersion {
		return fmt.Errorf("unexpected network collector contract")
	}
	if inv.CollectedAt.IsZero() || strings.TrimSpace(inv.Platform) == "" || strings.TrimSpace(inv.Architecture) == "" {
		return fmt.Errorf("network inventory identity is incomplete")
	}
	if len(inv.Endpoints) > maxEndpoints {
		return fmt.Errorf("network inventory exceeds maximum record count")
	}
	seen := map[string]struct{}{}
	last := ""
	for i, e := range inv.Endpoints {
		if e.ID == "" || (e.Protocol != "TCP" && e.Protocol != "UDP") || (e.TransportState != "LISTEN" && e.TransportState != "BOUND") || (e.AddressFamily != "IPV4" && e.AddressFamily != "IPV6") || strings.TrimSpace(e.LocalAddress) == "" || e.LocalPort == 0 || strings.TrimSpace(e.InterfaceBinding.Class) == "" || strings.TrimSpace(e.Owner.State) == "" || strings.TrimSpace(e.CollectionSource) == "" || e.Confidence == "" {
			return fmt.Errorf("network endpoint %d is incomplete", i)
		}
		if _, ok := seen[e.ID]; ok {
			return fmt.Errorf("duplicate network endpoint id %q", e.ID)
		}
		seen[e.ID] = struct{}{}
		k := endpointSortKey(e)
		if last != "" && k < last {
			return fmt.Errorf("network endpoints are not deterministically ordered")
		}
		last = k
	}
	if inv.Summary != summarize(inv.Endpoints) {
		return fmt.Errorf("network summary does not match records")
	}
	return evidence.ValidateAll(inv.Evidence)
}

func newEndpoint(protocol, state, address string, port uint16, owner Owner, socketID, source string) Endpoint {
	protocol = strings.ToUpper(strings.TrimSpace(protocol))
	state = strings.ToUpper(strings.TrimSpace(state))
	address = normalizeAddress(address)
	family := "IPV4"
	if strings.Contains(address, ":") {
		family = "IPV6"
	}
	if owner.State == "" {
		if owner.PID > 0 {
			owner.State = "OBSERVED"
		} else {
			owner.State = "UNAVAILABLE"
		}
	}
	e := Endpoint{Protocol: protocol, TransportState: state, AddressFamily: family, LocalAddress: address, LocalPort: port, Owner: owner, SocketIdentity: strings.TrimSpace(socketID), CollectionSource: source, Confidence: evidence.ConfidenceHigh}
	e.InterfaceBinding = classifyBinding(address)
	e.ID = stableID(e)
	return e
}

func normalizeEndpoints(in []Endpoint) []Endpoint {
	out := make([]Endpoint, 0, len(in))
	seen := map[string]struct{}{}
	for _, e := range in {
		e.Protocol = strings.ToUpper(strings.TrimSpace(e.Protocol))
		e.TransportState = strings.ToUpper(strings.TrimSpace(e.TransportState))
		e.LocalAddress = normalizeAddress(e.LocalAddress)
		if e.AddressFamily == "" {
			if strings.Contains(e.LocalAddress, ":") {
				e.AddressFamily = "IPV6"
			} else {
				e.AddressFamily = "IPV4"
			}
		}
		e.InterfaceBinding = classifyBinding(e.LocalAddress)
		if e.Owner.State == "" {
			if e.Owner.PID > 0 {
				e.Owner.State = "OBSERVED"
			} else {
				e.Owner.State = "UNAVAILABLE"
			}
		}
		if e.CollectionSource == "" {
			e.CollectionSource = "platform local socket provider"
		}
		if e.Confidence == "" {
			e.Confidence = evidence.ConfidenceHigh
		}
		e.ID = stableID(e)
		if _, ok := seen[e.ID]; ok {
			continue
		}
		seen[e.ID] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return endpointSortKey(out[i]) < endpointSortKey(out[j]) })
	if len(out) > maxEndpoints {
		out = out[:maxEndpoints]
	}
	return out
}

func stableID(e Endpoint) string {
	basis := strings.Join([]string{e.Protocol, e.AddressFamily, e.LocalAddress, strconv.Itoa(int(e.LocalPort)), strconv.Itoa(e.Owner.PID), e.Owner.ServiceName, e.SocketIdentity}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return "net-" + hex.EncodeToString(sum[:10])
}
func endpointSortKey(e Endpoint) string {
	return e.Protocol + "\x00" + e.AddressFamily + "\x00" + e.LocalAddress + "\x00" + fmt.Sprintf("%05d", e.LocalPort) + "\x00" + fmt.Sprintf("%010d", e.Owner.PID) + "\x00" + e.ID
}

func classifyBinding(address string) Binding {
	a := normalizeAddress(address)
	if isWildcard(a) {
		return Binding{Class: "ALL_INTERFACES", IsWildcard: true, Interfaces: interfaceNames()}
	}
	ip := net.ParseIP(strings.Trim(a, "[]"))
	if ip != nil && ip.IsLoopback() {
		return Binding{Class: "LOOPBACK", IsLoopback: true, Interfaces: interfacesForIP(ip)}
	}
	if ip != nil {
		return Binding{Class: "NON_LOOPBACK", Interfaces: interfacesForIP(ip)}
	}
	return Binding{Class: "UNKNOWN"}
}
func isWildcard(a string) bool { return a == "0.0.0.0" || a == "::" || a == "*" || a == "[::]" }
func normalizeAddress(a string) string {
	a = strings.TrimSpace(strings.Trim(a, "[]"))
	if a == "" || a == "*" {
		return "0.0.0.0"
	}
	if ip := net.ParseIP(a); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return a
}
func interfaceNames() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ifs))
	for _, i := range ifs {
		out = append(out, i.Name)
	}
	sort.Strings(out)
	return out
}
func interfacesForIP(ip net.IP) []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := []string{}
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			host, _, err := net.ParseCIDR(a.String())
			if err != nil {
				host = net.ParseIP(strings.Split(a.String(), "%")[0])
			}
			if host != nil && host.Equal(ip) {
				out = append(out, i.Name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

func summarize(items []Endpoint) Summary {
	var s Summary
	s.Endpoints = len(items)
	for _, e := range items {
		if e.Protocol == "TCP" {
			s.TCPListeners++
		} else if e.Protocol == "UDP" {
			s.UDPBound++
		}
		if e.AddressFamily == "IPV4" {
			s.IPv4++
		} else {
			s.IPv6++
		}
		switch e.InterfaceBinding.Class {
		case "ALL_INTERFACES":
			s.AllInterfaces++
		case "LOOPBACK":
			s.LoopbackOnly++
		case "NON_LOOPBACK":
			s.NonLoopback++
		}
		if e.Owner.PID > 0 {
			s.OwnedByProcess++
		} else {
			s.OwnerUnavailable++
		}
		if strings.TrimSpace(e.Owner.ServiceName) != "" {
			s.OwnedByService++
		}
	}
	return s
}
func buildEvidence(inv Inventory) []evidence.Observation {
	at := inv.CollectedAt
	out := []evidence.Observation{
		evidence.NewObserved("network.platform", inv.Platform, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.architecture", inv.Architecture, "Go runtime", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.inventory.count", len(inv.Endpoints), "normalized local endpoint inventory", at, evidence.ConfidenceExact),
		evidence.NewObserved("network.inventory.summary", inv.Summary, "normalized local endpoint inventory", at, evidence.ConfidenceHigh),
	}
	for _, src := range inv.Sources {
		key := "network.source." + slug(src.ID)
		if src.State == evidence.StateObserved {
			out = append(out, evidence.NewObserved(key, map[string]any{"state": string(src.State), "item_count": src.ItemCount}, src.Source, at, evidence.ConfidenceHigh))
		} else {
			st := src.State
			if st == "" {
				st = evidence.StateUnavailable
			}
			out = append(out, evidence.NewState(key, st, src.Source, at, evidence.ConfidenceLow, fallback(src.Reason, "network provider unavailable")))
		}
	}
	for _, e := range inv.Endpoints {
		out = append(out, evidence.NewObserved("network.endpoint."+e.ID, e, e.CollectionSource, at, e.Confidence))
	}
	return out
}
func addSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	if state == "" {
		state = evidence.StateUnavailable
	}
	s := SourceStatus{ID: strings.TrimSpace(id), State: state, Source: fallback(source, "platform local socket provider"), ItemCount: count, Reason: strings.TrimSpace(reason)}
	inv.Sources = append(inv.Sources, s)
	if state != evidence.StateObserved && state != evidence.StateNotApplicable && s.Reason != "" {
		inv.Degraded = append(inv.Degraded, s.ID+": "+s.Reason)
	}
}
func normalizeSources(in []SourceStatus) []SourceStatus {
	out := append([]SourceStatus(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func fallback(v, f string) string {
	if strings.TrimSpace(v) == "" {
		return f
	}
	return strings.TrimSpace(v)
}
func slug(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	var b strings.Builder
	lastDash := false
	for _, r := range v {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
