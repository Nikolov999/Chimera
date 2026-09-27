//go:build darwin

package accounts

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatform(ctx context.Context, inv *Inventory) {
	dscl, err := exec.LookPath("dscl")
	if err != nil {
		addSource(inv, "darwin-opendirectory", evidence.StateUnavailable, "dscl local OpenDirectory provider", 0, "dscl not found")
		return
	}
	raw, err := exec.CommandContext(ctx, dscl, ".", "-list", "/Users", "UniqueID").Output()
	if err != nil {
		addSource(inv, "darwin-opendirectory", evidence.StateUnavailable, "dscl local OpenDirectory provider", 0, err.Error())
		return
	}
	lines := strings.Split(string(raw), "\n")
	names := []string{}
	uidByName := map[string]string{}
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) >= 2 {
			names = append(names, f[0])
			uidByName[f[0]] = f[len(f)-1]
		}
	}
	sort.Strings(names)

	groups, groupReason := collectDarwinGroups(ctx, dscl)
	inv.Groups = groups
	if groupReason != "" {
		addSource(inv, "darwin-groups", evidence.StateDegraded, "dscl local group provider", len(groups), groupReason)
	} else {
		addSource(inv, "darwin-groups", evidence.StateObserved, "dscl local group provider", len(groups), "")
	}
	memberGroups := map[string][]string{}
	byGID := map[string]string{}
	for _, g := range groups {
		if g.GID != "" {
			byGID[g.GID] = g.Name
		}
		for _, m := range g.Members {
			memberGroups[m] = append(memberGroups[m], g.Name)
		}
	}

	degraded := 0
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		attrs, reason := readDarwinUser(ctx, dscl, name)
		if reason != "" {
			degraded++
		}
		uid := uidByName[name]
		gid := attrs["PrimaryGroupID"]
		groups := append([]string(nil), memberGroups[name]...)
		if p := byGID[gid]; p != "" {
			groups = append(groups, p)
		}
		nuid, _ := strconv.Atoi(uid)
		privileged := nuid == 0
		basis := []string{}
		if nuid == 0 {
			basis = append(basis, "uid 0")
		}
		for _, g := range uniqueSorted(groups) {
			if darwinPrivilegedGroup(g) {
				privileged = true
				basis = append(basis, "member of privileged group "+g)
			}
		}
		shell := attrs["UserShell"]
		service, bsvc := darwinServiceClassification(name, nuid, shell)
		kind := "HUMAN"
		if service {
			kind = "SERVICE"
		} else if nuid < 500 {
			kind = "SYSTEM"
		}
		enabled := "UNKNOWN"
		authState := "OBSERVED"
		passState := "UNKNOWN"
		authReason := "password material is not read; only disabled-account marker is inspected"
		authRaw, authErr := exec.CommandContext(ctx, dscl, ".", "-read", "/Users/"+name, "AuthenticationAuthority").CombinedOutput()
		if authErr == nil {
			if strings.Contains(strings.ToLower(string(authRaw)), "disableduser") {
				enabled = "DISABLED"
				passState = "LOCKED"
			} else {
				enabled = "ENABLED"
			}
		} else {
			authState = "UNAVAILABLE"
			authReason = "AuthenticationAuthority metadata unavailable"
		}
		login := darwinLoginCapability(shell)
		if enabled == "DISABLED" {
			login = "LOGIN_DISABLED"
		}
		inv.Accounts = append(inv.Accounts, Account{Name: name, Principal: name, UID: uid, GID: gid, Home: attrs["NFSHomeDirectory"], Shell: shell, Description: attrs["RealName"], AccountType: kind, EnabledState: enabled, LoginCapability: login, Privileged: privileged, PrivilegeBasis: basis, ServiceAccount: service, ServiceBasis: bsvc, Groups: groups, Authentication: AuthenticationMetadata{State: authState, PasswordState: passState, PasswordRequired: "UNKNOWN", PasswordExpires: "UNKNOWN", PasswordChangeable: "UNKNOWN", Source: "OpenDirectory AuthenticationAuthority state only", Reason: authReason}, CollectionSource: "OpenDirectory via dscl", Confidence: evidence.ConfidenceHigh})
		if len(inv.Accounts) >= maxAccounts {
			break
		}
	}
	state := evidence.StateObserved
	reason := ""
	if degraded > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("%d user records had unavailable optional attributes", degraded)
	}
	addSource(inv, "darwin-opendirectory", state, "dscl local OpenDirectory provider", len(inv.Accounts), reason)
}

func readDarwinUser(ctx context.Context, dscl, name string) (map[string]string, string) {
	raw, err := exec.CommandContext(ctx, dscl, ".", "-read", "/Users/"+name, "PrimaryGroupID", "NFSHomeDirectory", "UserShell", "RealName").Output()
	if err != nil {
		return map[string]string{}, err.Error()
	}
	out := map[string]string{}
	for _, ln := range strings.Split(string(raw), "\n") {
		if i := strings.Index(ln, ":"); i > 0 {
			k := strings.TrimSpace(ln[:i])
			v := strings.TrimSpace(ln[i+1:])
			if k != "" && v != "" {
				out[k] = v
			}
		}
	}
	return out, ""
}
func collectDarwinGroups(ctx context.Context, dscl string) ([]Group, string) {
	raw, err := exec.CommandContext(ctx, dscl, ".", "-list", "/Groups", "PrimaryGroupID").Output()
	if err != nil {
		return nil, err.Error()
	}
	names := []string{}
	gid := map[string]string{}
	for _, ln := range strings.Split(string(raw), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 {
			names = append(names, f[0])
			gid[f[0]] = f[len(f)-1]
		}
	}
	sort.Strings(names)
	out := []Group{}
	degraded := 0
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		members := []string{}
		r, e := exec.CommandContext(ctx, dscl, ".", "-read", "/Groups/"+name, "GroupMembership").Output()
		if e == nil {
			for _, ln := range strings.Split(string(r), "\n") {
				if strings.HasPrefix(strings.TrimSpace(ln), "GroupMembership:") {
					members = strings.Fields(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ln), "GroupMembership:")))
				}
			}
		} else {
			degraded++
		}
		out = append(out, Group{Name: name, GID: gid[name], Privileged: darwinPrivilegedGroup(name), Members: members, CollectionSource: "OpenDirectory via dscl", Confidence: evidence.ConfidenceHigh})
		if len(out) >= maxGroups {
			break
		}
	}
	reason := ""
	if degraded > 0 {
		reason = fmt.Sprintf("%d groups had unavailable membership metadata", degraded)
	}
	return out, reason
}
func darwinPrivilegedGroup(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "admin", "wheel", "root":
		return true
	}
	return false
}
func darwinLoginCapability(shell string) string {
	s := strings.ToLower(strings.TrimSpace(shell))
	if s == "" {
		return "UNKNOWN"
	}
	if strings.Contains(s, "nologin") || strings.HasSuffix(s, "/false") {
		return "LOGIN_DISABLED"
	}
	return "LOGIN_CAPABLE"
}
func darwinServiceClassification(name string, uid int, shell string) (bool, []string) {
	b := []string{}
	if uid > 0 && uid < 500 {
		b = append(b, "system-range uid")
	}
	if darwinLoginCapability(shell) == "LOGIN_DISABLED" {
		b = append(b, "non-interactive shell")
	}
	if strings.HasPrefix(name, "_") {
		b = append(b, "macOS service account naming convention")
	}
	return len(b) > 0, b
}
