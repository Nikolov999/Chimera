//go:build linux

package accounts

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const maxLinuxAuthFileBytes = 2 << 20

func collectLinuxAuthPosture(ctx context.Context, inv *Inventory) {
	inv.LinuxAuthPosture = collectLinuxAuthentication(ctx, "/etc")
}

func collectLinuxAuthentication(ctx context.Context, etcRoot string) LinuxAuthPosture {
	provider := "Linux PAM/login policy parser"
	p := LinuxAuthPosture{Source: provider}
	var problems []string

	pamDir := filepath.Join(etcRoot, "pam.d")
	dirCfg, err := inspectLinuxAuthPath(pamDir, "PAM_DIRECTORY")
	p.ConfigPaths = append(p.ConfigPaths, dirCfg)
	if err == nil {
		entries, readErr := os.ReadDir(pamDir)
		if readErr != nil {
			problems = append(problems, pamDir+": "+readErr.Error())
		} else {
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			for _, entry := range entries {
				if ctx.Err() != nil {
					break
				}
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				if len(p.PAMRules) >= maxLinuxPAMRules || len(p.ConfigPaths) >= maxLinuxAuthFiles {
					problems = append(problems, "PAM configuration exceeds bounded record limits")
					break
				}
				path := filepath.Join(pamDir, entry.Name())
				cfg, rules, parseErr := parsePAMFile(ctx, path, entry.Name())
				p.ConfigPaths = append(p.ConfigPaths, cfg)
				p.PAMRules = append(p.PAMRules, rules...)
				if parseErr != nil {
					problems = append(problems, path+": "+parseErr.Error())
				}
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		problems = append(problems, pamDir+": "+err.Error())
	}

	loginPath := filepath.Join(etcRoot, "login.defs")
	cfg, lp, loginErr := parseLoginDefs(ctx, loginPath)
	p.ConfigPaths = append(p.ConfigPaths, cfg)
	p.LoginPolicy = lp
	if loginErr != nil && !errors.Is(loginErr, fs.ErrNotExist) {
		problems = append(problems, loginPath+": "+loginErr.Error())
	}

	parseFaillockConfig(ctx, filepath.Join(etcRoot, "security", "faillock.conf"), &p, &problems)
	parsePwqualityConfig(ctx, filepath.Join(etcRoot, "security", "pwquality.conf"), &p, &problems)
	parsePwhistoryConfig(ctx, filepath.Join(etcRoot, "security", "pwhistory.conf"), &p, &problems)

	// Module-line options can override or provide posture when dedicated
	// configuration files are absent. Fold only safe numeric/boolean metadata.
	for _, r := range p.PAMRules {
		switch r.Module {
		case "pam_faillock.so", "pam_tally2.so", "pam_tally.so":
			if r.Deny > 0 {
				p.Tuning.FaillockDeny = r.Deny
			}
			if r.UnlockTime > 0 {
				p.Tuning.FaillockUnlockTime = r.UnlockTime
			}
			if r.EvenRoot {
				p.Tuning.EvenDenyRoot = true
			}
		case "pam_pwquality.so", "pam_passwdqc.so", "pam_cracklib.so":
			if r.MinLen > 0 {
				p.Tuning.PwqualityMinLen = r.MinLen
			}
			if r.Retry > 0 {
				p.Tuning.PwqualityRetry = r.Retry
			}
		case "pam_pwhistory.so":
			if r.Remember > 0 {
				p.Tuning.PasswordRemember = r.Remember
			}
		case "pam_unix.so":
			if r.Remember > 0 {
				p.Tuning.PasswordRemember = r.Remember
			}
		}
	}

	switch {
	case ctx.Err() != nil:
		p.State = evidence.StateUnavailable
		p.Reason = "Linux authentication collection cancelled or timed out: " + ctx.Err().Error()
	case !directoryExists(pamDir) && errors.Is(loginErr, fs.ErrNotExist):
		p.State = evidence.StateUnavailable
		p.Reason = "PAM configuration and /etc/login.defs are absent"
	case len(p.PAMRules) == 0 && p.LoginPolicy.State != evidence.StateObserved:
		denied := false
		for _, c := range p.ConfigPaths {
			if c.State == evidence.StateDenied {
				denied = true
				break
			}
		}
		if denied {
			p.State = evidence.StateDenied
			p.Reason = "PAM/login policy configuration is not readable in the current privilege context"
		} else {
			p.State = evidence.StateUnavailable
			p.Reason = "no usable PAM/login policy configuration was parsed"
		}
	case len(problems) > 0:
		p.State = evidence.StateDegraded
		p.Reason = strings.Join(uniqueSorted(problems), "; ")
	default:
		p.State = evidence.StateObserved
	}
	return normalizeLinuxAuthPosture("linux", p)
}

func parsePAMFile(ctx context.Context, path, service string) (LinuxAuthConfigPath, []LinuxPAMRule, error) {
	cfg, statErr := inspectLinuxAuthPath(path, "PAM_FILE")
	if statErr != nil {
		return cfg, nil, statErr
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			cfg.State = evidence.StateDenied
			cfg.Reason = "permission denied reading PAM configuration"
		} else {
			cfg.State = evidence.StateUnavailable
			cfg.Reason = err.Error()
		}
		return cfg, nil, err
	}
	defer f.Close()
	r := io.LimitReader(f, maxLinuxAuthFileBytes+1)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 256<<10)
	var rules []LinuxPAMRule
	lineNo := 0
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			cfg.Parsed = false
			return cfg, rules, err
		}
		lineNo++
		text := stripHashComment(sc.Text())
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		// Debian-style @include lines are useful chain metadata but contain no
		// module invocation. The included service file itself is parsed from
		// /etc/pam.d, so no synthetic module rule is needed here.
		if strings.HasPrefix(fields[0], "@") {
			continue
		}
		if len(fields) < 3 {
			continue
		}
		typ := strings.TrimPrefix(strings.ToLower(fields[0]), "-")
		if typ != "auth" && typ != "account" && typ != "password" && typ != "session" {
			continue
		}
		control, moduleIndex := parsePAMControl(fields)
		if moduleIndex < 0 || moduleIndex >= len(fields) {
			continue
		}
		module := filepath.Base(fields[moduleIndex])
		rule := LinuxPAMRule{Service: service, Type: typ, Control: control, Module: module, Source: path, Line: lineNo}
		parsePAMOptions(fields[moduleIndex+1:], &rule)
		rule.ID = stableLinuxAuthID("pam-rule", rule.Source, fmt.Sprint(rule.Line), rule.Service, rule.Type, rule.Control, rule.Module)
		rules = append(rules, rule)
		if len(rules) >= maxLinuxPAMRules {
			break
		}
	}
	if err := sc.Err(); err != nil {
		cfg.Parsed = false
		return cfg, rules, err
	}
	cfg.Parsed = true
	cfg.Reason = ""
	return cfg, rules, nil
}

func parsePAMControl(fields []string) (string, int) {
	if len(fields) < 3 {
		return "", -1
	}
	if strings.HasPrefix(fields[1], "[") {
		end := 1
		for end < len(fields) && !strings.HasSuffix(fields[end], "]") {
			end++
		}
		if end >= len(fields)-1 {
			return "", -1
		}
		return strings.Join(fields[1:end+1], " "), end + 1
	}
	return fields[1], 2
}

func parsePAMOptions(opts []string, r *LinuxPAMRule) {
	for _, raw := range opts {
		token := strings.TrimSpace(strings.ToLower(raw))
		switch token {
		case "nullok", "nullok_secure":
			r.NullOK = true
		case "no_pass_expiry":
			r.NoPassExp = true
		case "even_deny_root":
			r.EvenRoot = true
		case "local_users_only":
			r.LocalUsers = true
		case "yescrypt", "sha512", "sha256", "md5", "bigcrypt", "blowfish":
			r.Hash = strings.ToUpper(token)
		}
		if k, v, ok := strings.Cut(token, "="); ok {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				continue
			}
			switch k {
			case "deny":
				r.Deny = n
			case "unlock_time":
				r.UnlockTime = n
			case "retry":
				r.Retry = n
			case "minlen":
				r.MinLen = n
			case "remember":
				r.Remember = n
			}
		}
	}
}

func parseLoginDefs(ctx context.Context, path string) (LinuxAuthConfigPath, LinuxLoginPolicy, error) {
	cfg, statErr := inspectLinuxAuthPath(path, "LOGIN_DEFS")
	lp := LinuxLoginPolicy{Source: path, State: evidence.StateUnavailable, Confidence: evidence.ConfidenceLow, Reason: "login.defs policy was not observable"}
	if statErr != nil {
		return cfg, lp, statErr
	}
	values, err := parseKeyValueFile(ctx, path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			lp.State = evidence.StateDenied
			lp.Reason = "permission denied reading login.defs"
		} else {
			lp.Reason = err.Error()
		}
		return cfg, lp, err
	}
	cfg.Parsed = true
	cfg.Reason = ""
	lp.State = evidence.StateObserved
	lp.Confidence = evidence.ConfidenceExact
	lp.Reason = ""
	lp.MaxDays = parseNonNegative(values["PASS_MAX_DAYS"])
	lp.MinDays = parseNonNegative(values["PASS_MIN_DAYS"])
	lp.WarnAge = parseNonNegative(values["PASS_WARN_AGE"])
	lp.MinLength = parseNonNegative(values["PASS_MIN_LEN"])
	lp.EncryptMethod = strings.ToUpper(strings.TrimSpace(values["ENCRYPT_METHOD"]))
	return cfg, lp, nil
}

func parseFaillockConfig(ctx context.Context, path string, p *LinuxAuthPosture, problems *[]string) {
	cfg, statErr := inspectLinuxAuthPath(path, "FAILLOCK_CONFIG")
	if errors.Is(statErr, fs.ErrNotExist) {
		return
	}
	p.ConfigPaths = append(p.ConfigPaths, cfg)
	if statErr != nil {
		*problems = append(*problems, path+": "+statErr.Error())
		return
	}
	vals, err := parseKeyValueFile(ctx, path)
	if err != nil {
		*problems = append(*problems, path+": "+err.Error())
		return
	}
	p.ConfigPaths[len(p.ConfigPaths)-1].Parsed = true
	p.ConfigPaths[len(p.ConfigPaths)-1].Reason = ""
	p.Tuning.FaillockDeny = parseNonNegative(vals["deny"])
	p.Tuning.FaillockUnlockTime = parseNonNegative(vals["unlock_time"])
	_, p.Tuning.EvenDenyRoot = vals["even_deny_root"]
}

func parsePwqualityConfig(ctx context.Context, path string, p *LinuxAuthPosture, problems *[]string) {
	cfg, statErr := inspectLinuxAuthPath(path, "PWQUALITY_CONFIG")
	if errors.Is(statErr, fs.ErrNotExist) {
		return
	}
	p.ConfigPaths = append(p.ConfigPaths, cfg)
	if statErr != nil {
		*problems = append(*problems, path+": "+statErr.Error())
		return
	}
	vals, err := parseKeyValueFile(ctx, path)
	if err != nil {
		*problems = append(*problems, path+": "+err.Error())
		return
	}
	p.ConfigPaths[len(p.ConfigPaths)-1].Parsed = true
	p.ConfigPaths[len(p.ConfigPaths)-1].Reason = ""
	p.Tuning.PwqualityMinLen = parseNonNegative(vals["minlen"])
	p.Tuning.PwqualityMinClass = parseNonNegative(vals["minclass"])
	p.Tuning.PwqualityRetry = parseNonNegative(vals["retry"])
}

func parsePwhistoryConfig(ctx context.Context, path string, p *LinuxAuthPosture, problems *[]string) {
	cfg, statErr := inspectLinuxAuthPath(path, "PWHISTORY_CONFIG")
	if errors.Is(statErr, fs.ErrNotExist) {
		return
	}
	p.ConfigPaths = append(p.ConfigPaths, cfg)
	if statErr != nil {
		*problems = append(*problems, path+": "+statErr.Error())
		return
	}
	vals, err := parseKeyValueFile(ctx, path)
	if err != nil {
		*problems = append(*problems, path+": "+err.Error())
		return
	}
	p.ConfigPaths[len(p.ConfigPaths)-1].Parsed = true
	p.ConfigPaths[len(p.ConfigPaths)-1].Reason = ""
	p.Tuning.PasswordRemember = parseNonNegative(vals["remember"])
}

func parseKeyValueFile(ctx context.Context, path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, maxLinuxAuthFileBytes+1))
	sc.Buffer(make([]byte, 64<<10), 256<<10)
	out := map[string]string{}
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		line := strings.TrimSpace(stripHashComment(sc.Text()))
		if line == "" {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			out[fields[0]] = fields[1]
		} else if len(fields) == 1 {
			out[fields[0]] = "true"
		}
	}
	return out, sc.Err()
}

func inspectLinuxAuthPath(path, kind string) (LinuxAuthConfigPath, error) {
	item := LinuxAuthConfigPath{Path: path, Kind: kind, State: evidence.StateUnavailable, Source: path, Confidence: evidence.ConfidenceLow, Reason: "path metadata is unavailable"}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			item.State = evidence.StateDenied
			item.Reason = "permission denied reading path metadata"
		} else if errors.Is(err, fs.ErrNotExist) {
			item.Reason = "path does not exist"
		} else {
			item.Reason = err.Error()
		}
		item.ID = stableLinuxAuthID("auth-config", path, kind)
		return item, err
	}
	item.State = evidence.StateObserved
	item.Confidence = evidence.ConfidenceExact
	item.Reason = ""
	item.Mode = formatFileMode(info.Mode())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		item.UID = st.Uid
		item.GID = st.Gid
	}
	item.InsecureBasis = linuxAuthPermissionRisks(info.Mode(), item.UID)
	item.Insecure = len(item.InsecureBasis) > 0
	item.ID = stableLinuxAuthID("auth-config", path, kind)
	return item, nil
}

func linuxAuthPermissionRisks(mode fs.FileMode, uid uint32) []string {
	var out []string
	if uid != 0 {
		out = append(out, "configuration is not owned by root")
	}
	if mode.Perm()&0022 != 0 {
		out = append(out, "configuration is group/world writable")
	}
	return out
}

func stripHashComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func parseNonNegative(v string) int {
	v = strings.TrimSpace(v)
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func directoryExists(path string) bool { info, err := os.Stat(path); return err == nil && info.IsDir() }
