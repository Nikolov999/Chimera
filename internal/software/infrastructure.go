package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxInfrastructureItems = 512

// InfrastructureItem is the normalized server/infrastructure record.
// Installed and Running are separate facts: a running but unattributed binary is
// preserved as such rather than being promoted to an installed package claim.
type InfrastructureItem struct {
	ID               string              `json:"id"`
	Role             string              `json:"role"`
	Family           string              `json:"family"`
	Product          string              `json:"product"`
	Version          string              `json:"version"`
	PackageID        string              `json:"package_id"`
	InstallPath      string              `json:"install_path"`
	Installed        bool                `json:"installed"`
	Running          bool                `json:"running"`
	RunningInstances []string            `json:"running_instances,omitempty"`
	ExecutablePaths  []string            `json:"executable_paths,omitempty"`
	DetectionSources []string            `json:"detection_sources"`
	CollectionSource string              `json:"collection_source"`
	Confidence       evidence.Confidence `json:"confidence"`
}

// HostActivityHint lets a full assessment reuse process/service metadata that
// was already collected by dedicated providers. It avoids launching a second
// Windows PowerShell/CIM process/service inventory solely for software
// infrastructure classification.
type HostActivityHint struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

type infrastructureActivity struct {
	Kind string
	Name string
	Path string
}

type infrastructureSignature struct {
	ID             string
	Role           string
	Family         string
	Product        string
	PackageAliases []string
	ProcessNames   []string
	ServiceNames   []string
}

var infrastructureSignatures = []infrastructureSignature{
	{ID: "openssh-server", Role: "remote-access", Family: "ssh", Product: "OpenSSH Server", PackageAliases: []string{"openssh-server", "openssh server"}, ProcessNames: []string{"sshd"}, ServiceNames: []string{"sshd", "ssh", "openssh ssh server"}},
	{ID: "nginx", Role: "web-server", Family: "nginx", Product: "nginx", PackageAliases: []string{"nginx"}, ProcessNames: []string{"nginx"}, ServiceNames: []string{"nginx"}},
	{ID: "apache-httpd", Role: "web-server", Family: "apache-httpd", Product: "Apache HTTP Server", PackageAliases: []string{"apache2", "httpd", "apache http server"}, ProcessNames: []string{"apache2", "httpd"}, ServiceNames: []string{"apache2", "httpd"}},
	{ID: "iis", Role: "web-server", Family: "iis", Product: "Microsoft IIS", PackageAliases: []string{"internet information services", "iis web core", "iis"}, ProcessNames: []string{"w3wp"}, ServiceNames: []string{"w3svc", "world wide web publishing service"}},
	{ID: "caddy", Role: "web-server", Family: "caddy", Product: "Caddy", PackageAliases: []string{"caddy"}, ProcessNames: []string{"caddy"}, ServiceNames: []string{"caddy"}},
	{ID: "lighttpd", Role: "web-server", Family: "lighttpd", Product: "lighttpd", PackageAliases: []string{"lighttpd"}, ProcessNames: []string{"lighttpd"}, ServiceNames: []string{"lighttpd"}},
	{ID: "postgresql", Role: "database", Family: "postgresql", Product: "PostgreSQL", PackageAliases: []string{"postgresql", "postgresql server"}, ProcessNames: []string{"postgres", "postmaster"}, ServiceNames: []string{"postgresql"}},
	{ID: "mysql", Role: "database", Family: "mysql", Product: "MySQL Server", PackageAliases: []string{"mysql-server", "mysql server", "mysql community server"}, ProcessNames: []string{"mysqld"}, ServiceNames: []string{"mysql", "mysql80"}},
	{ID: "mariadb", Role: "database", Family: "mariadb", Product: "MariaDB Server", PackageAliases: []string{"mariadb-server", "mariadb server"}, ProcessNames: []string{"mariadbd"}, ServiceNames: []string{"mariadb"}},
	{ID: "mssql", Role: "database", Family: "sql-server", Product: "Microsoft SQL Server", PackageAliases: []string{"mssql-server", "microsoft sql server"}, ProcessNames: []string{"sqlservr"}, ServiceNames: []string{"mssqlserver"}},
	{ID: "mongodb", Role: "database", Family: "mongodb", Product: "MongoDB Server", PackageAliases: []string{"mongodb-org", "mongodb server", "mongodb"}, ProcessNames: []string{"mongod"}, ServiceNames: []string{"mongodb", "mongod"}},
	{ID: "redis", Role: "database", Family: "redis", Product: "Redis Server", PackageAliases: []string{"redis-server", "redis server", "redis"}, ProcessNames: []string{"redis-server"}, ServiceNames: []string{"redis", "redis-server"}},
	{ID: "docker", Role: "container-runtime", Family: "docker", Product: "Docker Engine", PackageAliases: []string{"docker-ce", "docker.io", "docker engine", "docker desktop"}, ProcessNames: []string{"dockerd", "com.docker.backend"}, ServiceNames: []string{"docker", "com.docker.service"}},
	{ID: "containerd", Role: "container-runtime", Family: "containerd", Product: "containerd", PackageAliases: []string{"containerd", "containerd.io"}, ProcessNames: []string{"containerd"}, ServiceNames: []string{"containerd"}},
	{ID: "podman", Role: "container-runtime", Family: "podman", Product: "Podman", PackageAliases: []string{"podman"}, ProcessNames: []string{"podman"}, ServiceNames: []string{"podman"}},
	{ID: "crio", Role: "container-runtime", Family: "cri-o", Product: "CRI-O", PackageAliases: []string{"cri-o", "crio"}, ProcessNames: []string{"crio"}, ServiceNames: []string{"crio"}},
	{ID: "winrm", Role: "remote-management", Family: "winrm", Product: "Windows Remote Management", PackageAliases: []string{"windows remote management", "winrm"}, ProcessNames: []string{"wsmprovhost"}, ServiceNames: []string{"winrm", "windows remote management"}},
	{ID: "xrdp", Role: "remote-management", Family: "rdp", Product: "xrdp", PackageAliases: []string{"xrdp"}, ProcessNames: []string{"xrdp", "xrdp-sesman"}, ServiceNames: []string{"xrdp"}},
	{ID: "vnc", Role: "remote-management", Family: "vnc", Product: "VNC Server", PackageAliases: []string{"tigervnc-server", "vnc server", "realvnc", "tightvnc", "x11vnc"}, ProcessNames: []string{"x11vnc", "Xtigervnc", "vncserver", "winvnc"}, ServiceNames: []string{"vncserver", "winvnc"}},
	{ID: "samba", Role: "file-sharing", Family: "samba", Product: "Samba Server", PackageAliases: []string{"samba"}, ProcessNames: []string{"smbd", "samba"}, ServiceNames: []string{"smb", "smbd", "samba"}},
	{ID: "vsftpd", Role: "file-transfer", Family: "ftp", Product: "vsftpd", PackageAliases: []string{"vsftpd"}, ProcessNames: []string{"vsftpd"}, ServiceNames: []string{"vsftpd"}},
	{ID: "proftpd", Role: "file-transfer", Family: "ftp", Product: "ProFTPD", PackageAliases: []string{"proftpd"}, ProcessNames: []string{"proftpd"}, ServiceNames: []string{"proftpd"}},
	{ID: "hyper-v", Role: "hypervisor", Family: "hyper-v", Product: "Microsoft Hyper-V", PackageAliases: []string{"hyper-v"}, ProcessNames: []string{"vmms", "vmcompute"}, ServiceNames: []string{"vmms", "vmcompute", "hyper-v virtual machine management"}},
	{ID: "virtualbox", Role: "hypervisor", Family: "virtualbox", Product: "Oracle VM VirtualBox", PackageAliases: []string{"virtualbox", "oracle vm virtualbox"}, ProcessNames: []string{"vboxsvc", "vboxheadless"}, ServiceNames: []string{"vboxdrv"}},
	{ID: "vmware", Role: "hypervisor", Family: "vmware", Product: "VMware", PackageAliases: []string{"vmware workstation", "vmware fusion", "vmware player", "vmware tools"}, ProcessNames: []string{"vmware-vmx", "vmware-hostd", "vmware"}, ServiceNames: []string{"vmwarehostd", "vmware-hostd"}},
	{ID: "libvirt", Role: "hypervisor", Family: "libvirt", Product: "libvirt", PackageAliases: []string{"libvirt", "libvirt-daemon"}, ProcessNames: []string{"libvirtd", "virtqemud"}, ServiceNames: []string{"libvirtd", "virtqemud"}},
	{ID: "kubelet", Role: "orchestration", Family: "kubernetes", Product: "Kubernetes kubelet", PackageAliases: []string{"kubelet"}, ProcessNames: []string{"kubelet"}, ServiceNames: []string{"kubelet"}},
	{ID: "k3s", Role: "orchestration", Family: "kubernetes", Product: "K3s", PackageAliases: []string{"k3s"}, ProcessNames: []string{"k3s", "k3s-server"}, ServiceNames: []string{"k3s"}},
	{ID: "haproxy", Role: "proxy-load-balancer", Family: "haproxy", Product: "HAProxy", PackageAliases: []string{"haproxy"}, ProcessNames: []string{"haproxy"}, ServiceNames: []string{"haproxy"}},
	{ID: "traefik", Role: "proxy-load-balancer", Family: "traefik", Product: "Traefik", PackageAliases: []string{"traefik"}, ProcessNames: []string{"traefik"}, ServiceNames: []string{"traefik"}},
	{ID: "rabbitmq", Role: "message-broker", Family: "rabbitmq", Product: "RabbitMQ", PackageAliases: []string{"rabbitmq-server", "rabbitmq server"}, ProcessNames: []string{}, ServiceNames: []string{"rabbitmq-server", "rabbitmq"}},
	{ID: "mosquitto", Role: "message-broker", Family: "mqtt", Product: "Eclipse Mosquitto", PackageAliases: []string{"mosquitto"}, ProcessNames: []string{"mosquitto"}, ServiceNames: []string{"mosquitto"}},
}

func collectInfrastructureInventory(ctx context.Context, inv *Inventory) {
	collectInfrastructureInventoryWithActivity(ctx, inv, nil)
}

func collectInfrastructureInventoryWithActivity(ctx context.Context, inv *Inventory, hints []HostActivityHint) {
	activity := []infrastructureActivity{}
	if len(hints) > 0 {
		for _, h := range hints {
			kind := strings.ToLower(strings.TrimSpace(h.Kind))
			name := strings.TrimSpace(h.Name)
			if name == "" || (kind != "process" && kind != "service") {
				continue
			}
			activity = append(activity, infrastructureActivity{Kind: kind, Name: name, Path: strings.TrimSpace(h.Path)})
		}
		addInfrastructureSource(inv, "assessment-process-service-metadata-reuse", evidence.StateObserved, "dedicated process/service inventories reused by full assessment", len(activity), "")
	} else {
		var sources []SourceStatus
		activity, sources = collectPlatformInfrastructureActivity(ctx)
		for _, src := range sources {
			addInfrastructureSource(inv, src.ID, src.State, src.Source, src.ItemCount, src.Reason)
		}
	}
	inv.Infrastructure = classifyInfrastructure(inv.Items, activity)
	installedCount := 0
	for _, item := range inv.Infrastructure {
		if item.Installed {
			installedCount++
		}
	}
	addInfrastructureSource(inv, "installed-software-classifier", evidence.StateObserved, "normalized installed-software inventory", installedCount, "")
	inv.InfrastructureSources = normalizeSourceStatuses(inv.InfrastructureSources)
}

func classifyInfrastructure(items []Item, activity []infrastructureActivity) []InfrastructureItem {
	out := make([]InfrastructureItem, 0)
	for _, sig := range infrastructureSignatures {
		rec := InfrastructureItem{Role: sig.Role, Family: sig.Family, Product: sig.Product, Version: "UNKNOWN", PackageID: "UNKNOWN", InstallPath: "UNKNOWN", RunningInstances: []string{}, ExecutablePaths: []string{}, DetectionSources: []string{}, CollectionSource: "local infrastructure classification", Confidence: evidence.ConfidenceHigh}

		var best *Item
		for i := range items {
			if matchesAnyPackage(items[i], sig.PackageAliases) {
				if best == nil || confidenceRank(items[i].Confidence) > confidenceRank(best.Confidence) {
					cp := items[i]
					best = &cp
				}
				rec.Installed = true
				rec.DetectionSources = append(rec.DetectionSources, "installed-software:"+items[i].ID)
			}
		}
		if best != nil {
			rec.Version = normalizedOr(best.Version, "UNKNOWN")
			rec.PackageID = normalizedOr(best.PackageID, "UNKNOWN")
			rec.InstallPath = normalizedOr(best.InstallPath, "UNKNOWN")
			rec.Confidence = best.Confidence
		}

		for _, a := range activity {
			if activityMatches(a, sig) {
				rec.Running = true
				label := strings.ToLower(strings.TrimSpace(a.Kind)) + ":" + strings.TrimSpace(a.Name)
				if p := strings.TrimSpace(a.Path); p != "" {
					clean := filepath.Clean(p)
					label += "@" + clean
					rec.ExecutablePaths = append(rec.ExecutablePaths, clean)
				}
				rec.RunningInstances = append(rec.RunningInstances, label)
				rec.DetectionSources = append(rec.DetectionSources, strings.ToLower(strings.TrimSpace(a.Kind))+":"+strings.TrimSpace(a.Name))
			}
		}
		if !rec.Installed && !rec.Running {
			continue
		}
		rec.RunningInstances = uniqueSorted(rec.RunningInstances)
		rec.ExecutablePaths = uniqueSorted(rec.ExecutablePaths)
		rec.DetectionSources = uniqueSorted(rec.DetectionSources)
		if rec.Running && !rec.Installed {
			rec.Confidence = evidence.ConfidenceMedium
		}
		rec.ID = stableInfrastructureID(rec)
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		if out[i].Family != out[j].Family {
			return out[i].Family < out[j].Family
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > maxInfrastructureItems {
		out = out[:maxInfrastructureItems]
	}
	return out
}

func matchesAnyPackage(item Item, aliases []string) bool {
	product := normalizeMatchText(item.Product)
	packageID := normalizeMatchText(item.PackageID)
	for _, alias := range aliases {
		needle := normalizeMatchText(alias)
		if needle == "" {
			continue
		}
		// Package identifiers must match exactly; this prevents related client,
		// library, plugin, or helper packages from being promoted to a server.
		if packageID == needle {
			return true
		}
		// Human product names commonly append a release/version after the canonical
		// product name, so a token-boundary suffix is accepted there.
		if product == needle || strings.HasPrefix(product, needle+" ") {
			return true
		}
	}
	return false
}

func activityMatches(a infrastructureActivity, sig infrastructureSignature) bool {
	name := normalizeExecutableName(a.Name)
	switch strings.ToLower(strings.TrimSpace(a.Kind)) {
	case "process":
		for _, v := range sig.ProcessNames {
			if name == normalizeExecutableName(v) {
				return true
			}
		}
	case "service":
		n := normalizeMatchText(a.Name)
		for _, v := range sig.ServiceNames {
			needle := normalizeMatchText(v)
			if n == needle || (needle != "" && strings.Contains(" "+n+" ", " "+needle+" ")) {
				return true
			}
		}
	}
	return false
}

func normalizeExecutableName(s string) string {
	s = strings.TrimSpace(filepath.Base(strings.ReplaceAll(s, "\\", "/")))
	s = strings.TrimSuffix(strings.ToLower(s), ".exe")
	return s
}

func normalizeMatchText(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastSpace := true
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastSpace = false
		} else if !lastSpace {
			b.WriteByte(' ')
			lastSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

func stableInfrastructureID(item InfrastructureItem) string {
	identity := strings.ToLower(strings.Join([]string{item.Role, item.Family, item.Product}, "\x00"))
	sum := sha256.Sum256([]byte(identity))
	return "infra-" + hex.EncodeToString(sum[:10])
}

func addInfrastructureSource(inv *Inventory, id string, state evidence.State, source string, count int, reason string) {
	inv.InfrastructureSources = append(inv.InfrastructureSources, SourceStatus{ID: id, State: state, Source: source, ItemCount: count, Reason: strings.TrimSpace(reason)})
	if state == evidence.StateDenied || state == evidence.StateDegraded || state == evidence.StateUnavailable || state == evidence.StateUnsupported {
		if strings.TrimSpace(reason) != "" {
			inv.Degraded = append(inv.Degraded, "infrastructure "+id+": "+strings.TrimSpace(reason))
		}
	}
}

func normalizeSourceStatuses(in []SourceStatus) []SourceStatus {
	sort.Slice(in, func(i, j int) bool { return in[i].ID < in[j].ID })
	return in
}
