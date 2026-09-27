//go:build linux

package accounts

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

type passwdRecord struct{ name, uid, gid, gecos, home, shell string }
type authStatus struct{ state, lastChange, source string }

func collectPlatform(ctx context.Context, inv *Inventory) {
	uidMin := readUIDMin()
	groups, groupErr := readLinuxGroups(ctx)
	if groupErr != nil {
		st := evidence.StateUnavailable
		if errors.Is(groupErr, os.ErrPermission) {
			st = evidence.StateDenied
		}
		addSource(inv, "linux-group", st, "/etc/group", 0, groupErr.Error())
	} else {
		inv.Groups = groups
		addSource(inv, "linux-group", evidence.StateObserved, "/etc/group", len(groups), "")
	}

	passwd, err := readLinuxPasswd(ctx)
	if err != nil {
		st := evidence.StateUnavailable
		if errors.Is(err, os.ErrPermission) {
			st = evidence.StateDenied
		}
		addSource(inv, "linux-passwd", st, "/etc/passwd", 0, err.Error())
		return
	}
	addSource(inv, "linux-passwd", evidence.StateObserved, "/etc/passwd", len(passwd), "")

	// prefers local /etc/shadow metadata when the caller is already
	// permitted to read it. Only a derived state token and aging date are kept;
	// hash strings are discarded immediately and never enter Chimera evidence.
	authByName := map[string]authStatus{}
	shadowByName, shadowErr := readLinuxShadowPasswordStatus(ctx)
	if shadowErr == nil {
		for name, status := range shadowByName {
			authByName[name] = status
		}
		addSource(inv, "linux-shadow-password-state", evidence.StateObserved, "/etc/shadow derived password-state metadata (hash values discarded)", len(shadowByName), "")
	} else {
		st := evidence.StateUnavailable
		if errors.Is(shadowErr, os.ErrPermission) {
			st = evidence.StateDenied
		}
		addSource(inv, "linux-shadow-password-state", st, "/etc/shadow derived password-state metadata (hash values discarded)", 0, shadowErr.Error())
	}

	missing := make([]passwdRecord, 0)
	for _, p := range passwd {
		if _, ok := authByName[p.name]; !ok {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		fallbackStatus, authReason := readLinuxPasswordStatus(ctx, missing)
		for name, status := range fallbackStatus {
			authByName[name] = status
		}
		state := evidence.StateObserved
		if authReason != "" {
			state = evidence.StateDegraded
		}
		addSource(inv, "linux-password-status", state, "passwd -S status metadata (no password/hash values)", len(fallbackStatus), authReason)
	} else {
		addSource(inv, "linux-password-status", evidence.StateNotApplicable, "passwd -S status metadata (no password/hash values)", 0, "all local account password states were derived from permitted /etc/shadow metadata")
	}

	groupMap := map[string][]string{}
	groupPriv := map[string]bool{}
	for i := range inv.Groups {
		g := &inv.Groups[i]
		g.Privileged = linuxPrivilegedGroup(g.Name)
		groupPriv[strings.ToLower(g.Name)] = g.Privileged
		for _, m := range g.Members {
			groupMap[m] = append(groupMap[m], g.Name)
		}
	}
	byGID := map[string]string{}
	for _, g := range inv.Groups {
		if g.GID != "" {
			byGID[g.GID] = g.Name
		}
	}

	for _, p := range passwd {
		if err := ctx.Err(); err != nil {
			inv.Degraded = append(inv.Degraded, "linux account collection deadline reached: "+err.Error())
			break
		}
		uid, _ := strconv.Atoi(p.uid)
		groups := append([]string(nil), groupMap[p.name]...)
		if primary := byGID[p.gid]; primary != "" {
			groups = append(groups, primary)
		}
		privileged := uid == 0
		basis := []string{}
		if uid == 0 {
			basis = append(basis, "uid 0")
		}
		for _, g := range uniqueSorted(groups) {
			if groupPriv[strings.ToLower(g)] {
				privileged = true
				basis = append(basis, "member of privileged group "+g)
			}
		}
		login := linuxLoginCapability(p.shell)
		service, serviceBasis := linuxServiceClassification(p.name, uid, uidMin, p.shell)
		kind := "HUMAN"
		if service {
			kind = "SERVICE"
		} else if uid < uidMin {
			kind = "SYSTEM"
		}
		enabled := "UNKNOWN"
		auth := AuthenticationMetadata{
			State: "UNAVAILABLE", PasswordState: "UNKNOWN", PasswordRequired: "UNKNOWN", PasswordExpires: "UNKNOWN", PasswordChangeable: "UNKNOWN",
			Source: "local password-status metadata", Reason: "password-status metadata unavailable; credential material is never emitted",
		}
		if sm, ok := authByName[p.name]; ok {
			auth.State = "OBSERVED"
			auth.PasswordState = sm.state
			auth.LastPasswordChange = sm.lastChange
			auth.Source = sm.source
			auth.Reason = ""
			switch sm.state {
			case "LOCKED", "DISABLED":
				enabled = "DISABLED"
			case "PASSWORD_SET", "EMPTY":
				enabled = "ENABLED"
			}
		}
		inv.Accounts = append(inv.Accounts, Account{
			Name: p.name, Principal: p.name, UID: p.uid, GID: p.gid, Home: p.home, Shell: p.shell, Description: p.gecos,
			AccountType: kind, EnabledState: enabled, LoginCapability: login, Privileged: privileged, PrivilegeBasis: basis,
			ServiceAccount: service, ServiceBasis: serviceBasis, Groups: groups, Authentication: auth,
			CollectionSource: "/etc/passwd + /etc/group + derived local password-state metadata", Confidence: evidence.ConfidenceHigh,
		})
	}
}

func readLinuxPasswd(ctx context.Context) ([]passwdRecord, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []passwdRecord{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) < 7 {
			continue
		}
		out = append(out, passwdRecord{name: p[0], uid: p[2], gid: p[3], gecos: p[4], home: p[5], shell: p[6]})
		if len(out) >= maxAccounts {
			break
		}
	}
	return out, sc.Err()
}

func readLinuxGroups(ctx context.Context) ([]Group, error) {
	f, err := os.Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []Group{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		p := strings.Split(sc.Text(), ":")
		if len(p) < 4 || strings.TrimSpace(p[0]) == "" {
			continue
		}
		members := []string{}
		if strings.TrimSpace(p[3]) != "" {
			members = strings.Split(p[3], ",")
		}
		out = append(out, Group{Name: p[0], GID: p[2], Members: members, Privileged: linuxPrivilegedGroup(p[0]), CollectionSource: "/etc/group", Confidence: evidence.ConfidenceExact})
		if len(out) >= maxGroups {
			break
		}
	}
	return out, sc.Err()
}

func readLinuxShadowPasswordStatus(ctx context.Context) (map[string]authStatus, error) {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseLinuxShadowPasswordStatus(ctx, f)
}

func parseLinuxShadowPasswordStatus(ctx context.Context, r io.Reader) (map[string]authStatus, error) {
	out := map[string]authStatus{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		fields := strings.SplitN(sc.Text(), ":", 9)
		if len(fields) < 2 || strings.TrimSpace(fields[0]) == "" {
			continue
		}
		state := deriveShadowPasswordState(fields[1])
		last := ""
		if len(fields) >= 3 {
			if days, err := strconv.ParseInt(strings.TrimSpace(fields[2]), 10, 64); err == nil && days > 0 {
				last = time.Unix(days*86400, 0).UTC().Format("2006-01-02")
			}
		}
		out[fields[0]] = authStatus{
			state: state, lastChange: last,
			source: "/etc/shadow derived password-state metadata; hash value discarded and never retained",
		}
		if len(out) >= maxAccounts {
			break
		}
	}
	return out, sc.Err()
}

func deriveShadowPasswordState(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return "EMPTY"
	}
	if strings.HasPrefix(field, "!") || strings.HasPrefix(field, "*") {
		return "LOCKED"
	}
	return "PASSWORD_SET"
}

func readLinuxPasswordStatus(ctx context.Context, passwd []passwdRecord) (map[string]authStatus, string) {
	path, err := exec.LookPath("passwd")
	if err != nil {
		return map[string]authStatus{}, "passwd command not found"
	}
	out := map[string]authStatus{}
	reasons := []string{}
	for _, p := range passwd {
		if err := ctx.Err(); err != nil {
			reasons = append(reasons, "collection deadline reached: "+err.Error())
			break
		}
		raw, err := exec.CommandContext(ctx, path, "-S", p.name).CombinedOutput()
		if err != nil {
			continue
		}
		fields := strings.Fields(string(raw))
		if len(fields) < 2 {
			continue
		}
		state := "UNKNOWN"
		switch strings.ToUpper(fields[1]) {
		case "P", "PS":
			state = "PASSWORD_SET"
		case "L", "LK":
			state = "LOCKED"
		case "NP", "NL":
			state = "EMPTY"
		}
		last := ""
		if len(fields) >= 3 {
			last = fields[2]
		}
		out[p.name] = authStatus{state: state, lastChange: last, source: "passwd -S status metadata; no password/hash values returned to Chimera"}
	}
	if len(out) == 0 && len(passwd) > 0 {
		reasons = append(reasons, "passwd -S did not return readable status for local accounts")
	} else if len(out) < len(passwd) {
		reasons = append(reasons, "passwd -S returned status for only a subset of local accounts")
	}
	return out, strings.Join(uniqueSorted(reasons), "; ")
}

func readUIDMin() int {
	b, err := os.ReadFile("/etc/login.defs")
	if err != nil {
		return 1000
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "UID_MIN" {
			if n, err := strconv.Atoi(f[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 1000
}

func linuxLoginCapability(shell string) string {
	s := strings.ToLower(strings.TrimSpace(shell))
	if s == "" {
		return "UNKNOWN"
	}
	if strings.Contains(s, "nologin") || strings.HasSuffix(s, "/false") || s == "false" {
		return "LOGIN_DISABLED"
	}
	return "LOGIN_CAPABLE"
}

func linuxServiceClassification(name string, uid, uidMin int, shell string) (bool, []string) {
	b := []string{}
	if uid > 0 && uid < uidMin {
		b = append(b, "system-range uid")
	}
	if uid > 0 && linuxLoginCapability(shell) == "LOGIN_DISABLED" {
		b = append(b, "non-interactive shell")
	}
	n := strings.ToLower(name)
	if uid > 0 && uid < uidMin && (strings.Contains(n, "service") || strings.HasSuffix(n, "d")) {
		b = append(b, "service-like local account identity")
	}
	return len(b) > 0, b
}

func linuxPrivilegedGroup(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "root", "sudo", "wheel", "admin":
		return true
	}
	return false
}
