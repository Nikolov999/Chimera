//go:build darwin

package network

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	cmd := exec.CommandContext(ctx, "lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-FpcfPnT")
	b, err := cmd.Output()
	if err != nil {
		addSource(inv, "lsof-sockets", evidence.StateUnavailable, "macOS lsof local socket metadata", 0, err.Error())
		return
	}
	currentPID := 0
	currentName := ""
	currentFD := ""
	currentProto := ""
	currentListen := false
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	flushName := func(n string) {
		proto, addr, port, ok := parseLsofName(n, currentProto)
		if !ok {
			return
		}
		state := "BOUND"
		if proto == "TCP" {
			if !currentListen {
				return
			}
			state = "LISTEN"
		}
		owner := Owner{PID: currentPID, ProcessName: currentName, State: "OBSERVED", Source: "lsof process/socket metadata"}
		inv.Endpoints = append(inv.Endpoints, newEndpoint(proto, state, addr, port, owner, currentFD, "macOS lsof local socket metadata"))
	}
	pendingName := ""
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		tag := line[0]
		val := line[1:]
		switch tag {
		case 'p':
			if pendingName != "" {
				flushName(pendingName)
				pendingName = ""
			}
			currentPID, _ = strconv.Atoi(val)
			currentName = ""
			currentFD = ""
			currentProto = ""
			currentListen = false
		case 'c':
			currentName = val
		case 'f':
			if pendingName != "" {
				flushName(pendingName)
				pendingName = ""
			}
			currentFD = val
			currentProto = ""
			currentListen = false
		case 'P':
			currentProto = strings.ToUpper(val)
		case 'n':
			if pendingName != "" {
				flushName(pendingName)
			}
			pendingName = val
		case 'T':
			if strings.EqualFold(val, "ST=LISTEN") {
				currentListen = true
			}
		}
	}
	if pendingName != "" {
		flushName(pendingName)
	}
	if err := sc.Err(); err != nil {
		inv.Degraded = append(inv.Degraded, "lsof parse: "+err.Error())
	}
	addSource(inv, "lsof-sockets", evidence.StateObserved, "macOS lsof local socket/process metadata", len(inv.Endpoints), "")
}
func parseLsofName(n, protoHint string) (string, string, uint16, bool) {
	n = strings.TrimSpace(n)
	proto := strings.ToUpper(strings.TrimSpace(protoHint))
	if strings.HasPrefix(n, "TCP ") {
		proto = "TCP"
		n = strings.TrimSpace(strings.TrimPrefix(n, "TCP "))
	} else if strings.HasPrefix(n, "UDP ") {
		proto = "UDP"
		n = strings.TrimSpace(strings.TrimPrefix(n, "UDP "))
	}
	if proto != "TCP" && proto != "UDP" {
		return "", "", 0, false
	}
	if idx := strings.Index(n, "->"); idx >= 0 {
		n = n[:idx]
	}
	addr, port, err := splitHostPortLoose(n)
	if err != nil {
		return "", "", 0, false
	}
	return proto, addr, port, true
}
func splitHostPortLoose(v string) (string, uint16, error) {
	v = strings.TrimSpace(v)
	idx := strings.LastIndex(v, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("missing port")
	}
	host := strings.Trim(v[:idx], "[]")
	p64, err := strconv.ParseUint(v[idx+1:], 10, 16)
	if err != nil || p64 == 0 {
		return "", 0, fmt.Errorf("invalid port")
	}
	if host == "*" || host == "" {
		host = "0.0.0.0"
	}
	return host, uint16(p64), nil
}
