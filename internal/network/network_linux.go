//go:build linux

package network

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type linuxSocket struct {
	protocol, state, address string
	port                     uint16
	inode                    string
}

func collectPlatform(ctx context.Context, inv *Inventory) {
	tables := []struct{ path, protocol, family string }{{"/proc/net/tcp", "TCP", "IPV4"}, {"/proc/net/tcp6", "TCP", "IPV6"}, {"/proc/net/udp", "UDP", "IPV4"}, {"/proc/net/udp6", "UDP", "IPV6"}}
	sockets := []linuxSocket{}
	observedTables := 0
	for _, t := range tables {
		if err := ctx.Err(); err != nil {
			inv.Degraded = append(inv.Degraded, "network collection deadline: "+err.Error())
			break
		}
		rows, err := readProcNet(t.path, t.protocol, t.family)
		if err != nil {
			continue
		}
		observedTables++
		sockets = append(sockets, rows...)
	}
	if observedTables == 0 {
		addSource(inv, "proc-net", evidence.StateUnavailable, "Linux /proc/net socket tables", 0, "no readable /proc/net TCP/UDP socket table")
		return
	}
	owners, ownerErr := linuxSocketOwners(ctx)
	for _, s := range sockets {
		owner := owners[s.inode]
		if owner.State == "" {
			owner = Owner{State: "UNAVAILABLE", Source: "/proc/<pid>/fd ownership scan"}
		}
		e := newEndpoint(s.protocol, s.state, s.address, s.port, owner, s.inode, "Linux /proc/net + /proc/<pid>/fd")
		if s.addressFamilyHint() != e.AddressFamily {
			e.AddressFamily = s.addressFamilyHint()
		}
		inv.Endpoints = append(inv.Endpoints, e)
	}
	reason := ""
	state := evidence.StateObserved
	if ownerErr != nil {
		state = evidence.StateDegraded
		reason = ownerErr.Error()
	}
	addSource(inv, "proc-net", state, "Linux /proc/net socket tables + /proc/<pid>/fd", len(inv.Endpoints), reason)
}
func (s linuxSocket) addressFamilyHint() string {
	if strings.Contains(s.address, ":") {
		return "IPV6"
	}
	return "IPV4"
}

func readProcNet(path, protocol, family string) ([]linuxSocket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	out := []linuxSocket{}
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local := fields[1]
		st := strings.ToUpper(fields[3])
		inode := fields[9]
		if protocol == "TCP" && st != "0A" {
			continue
		}
		parts := strings.Split(local, ":")
		if len(parts) != 2 {
			continue
		}
		addr, err := decodeProcAddress(parts[0], family)
		if err != nil {
			continue
		}
		p64, err := strconv.ParseUint(parts[1], 16, 16)
		if err != nil || p64 == 0 {
			continue
		}
		state := "BOUND"
		if protocol == "TCP" {
			state = "LISTEN"
		}
		out = append(out, linuxSocket{protocol: protocol, state: state, address: addr, port: uint16(p64), inode: inode})
	}
	return out, sc.Err()
}
func decodeProcAddress(raw, family string) (string, error) {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return "", err
	}
	if family == "IPV4" {
		if len(b) != 4 {
			return "", fmt.Errorf("invalid ipv4 length")
		}
		return net.IPv4(b[3], b[2], b[1], b[0]).String(), nil
	}
	if len(b) != 16 {
		return "", fmt.Errorf("invalid ipv6 length")
	}
	// Linux /proc/net/tcp6 is emitted as four little-endian 32-bit words.
	for i := 0; i < 16; i += 4 {
		b[i], b[i+3] = b[i+3], b[i]
		b[i+1], b[i+2] = b[i+2], b[i+1]
	}
	return net.IP(b).String(), nil
}
func linuxSocketOwners(ctx context.Context) (map[string]Owner, error) {
	out := map[string]Owner{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out, err
	}
	denied := 0
	for _, de := range entries {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		if !de.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(de.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", de.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if os.IsPermission(err) {
				denied++
			}
			continue
		}
		name := readTrim(filepath.Join("/proc", de.Name(), "comm"))
		exe, _ := os.Readlink(filepath.Join("/proc", de.Name(), "exe"))
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if _, ok := out[inode]; !ok {
				out[inode] = Owner{PID: pid, ProcessName: name, Executable: exe, ServiceName: linuxServiceName(pid), State: "OBSERVED", Source: "/proc/<pid>/fd + /proc/<pid>/cgroup"}
			}
		}
	}
	if denied > 0 {
		return out, fmt.Errorf("%d process fd directories were permission-restricted; owner attribution may be incomplete", denied)
	}
	return out, nil
}
func linuxServiceName(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		for _, part := range strings.Split(line, "/") {
			if strings.HasSuffix(part, ".service") {
				return part
			}
		}
	}
	return ""
}
func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
