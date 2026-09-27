//go:build darwin

package filesystem

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func collectPlatformACLBoundaries(ctx context.Context, candidates []aclBoundaryCandidate) ([]ACLBoundaryRecord, SourceStatus, []string) {
	ls, err := exec.LookPath("ls")
	if err != nil {
		return nil, SourceStatus{ID: "acl-boundaries", State: evidence.StateUnavailable, Source: "macOS native extended ACL metadata via ls -lde", Reason: "ls provider not found"}, []string{"macOS ACL boundary inventory unavailable: ls provider not found"}
	}
	out := make([]ACLBoundaryRecord, 0, len(candidates))
	degraded := []string{}
	unresolved := 0
	for _, c := range candidates {
		if ctx != nil && ctx.Err() != nil {
			degraded = append(degraded, "ACL boundary inventory interrupted: "+ctx.Err().Error())
			break
		}
		rec := inspectDarwinACLBoundary(ctx, ls, c)
		out = append(out, rec)
		if rec.State != evidence.StateObserved {
			unresolved++
		}
	}
	state := evidence.StateObserved
	reason := ""
	if unresolved > 0 || len(degraded) > 0 {
		state = evidence.StateDegraded
		reason = fmt.Sprintf("macOS ACL boundary inventory completed with %d unresolved record(s)", unresolved)
	}
	if ctx != nil && ctx.Err() != nil && len(out) == 0 {
		state = evidence.StateUnavailable
		reason = ctx.Err().Error()
	}
	return out, SourceStatus{ID: "acl-boundaries", State: state, Source: "macOS native extended ACL metadata via ls -lde on selected high-impact paths", ItemCount: len(out), Reason: reason}, uniqueSorted(degraded)
}

func inspectDarwinACLBoundary(ctx context.Context, ls string, c aclBoundaryCandidate) ACLBoundaryRecord {
	rec := ACLBoundaryRecord{
		ID: stableACLBoundaryID(c.Path), Path: c.Path, Contexts: append([]string(nil), c.Contexts...),
		State: evidence.StateObserved, ACLModel: "MACOS_EXTENDED_ACL", DiscoverySources: append([]string(nil), c.Sources...),
		CollectionSource: "macOS native extended ACL listing (ls -lde)", Confidence: evidence.ConfidenceHigh,
	}
	info, err := os.Lstat(c.Path)
	if err != nil {
		if os.IsNotExist(err) {
			rec.Reason = "path does not exist on this host"
			return rec
		}
		if os.IsPermission(err) {
			rec.State = evidence.StateDenied
		} else {
			rec.State = evidence.StateUnavailable
		}
		rec.Reason = err.Error()
		return rec
	}
	rec.Exists = true
	rec.Directory = info.IsDir()
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		rec.OwnerID = strconv.FormatUint(uint64(st.Uid), 10)
	}

	raw, err := exec.CommandContext(ctx, ls, "-lde", c.Path).CombinedOutput()
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			rec.State = evidence.StateUnavailable
			rec.Reason = ctx.Err().Error()
		} else if strings.Contains(strings.ToLower(string(raw)), "permission denied") {
			rec.State = evidence.StateDenied
			rec.Reason = strings.TrimSpace(string(raw))
		} else {
			rec.State = evidence.StateUnavailable
			rec.Reason = fallback(strings.TrimSpace(string(raw)), err.Error())
		}
		rec.Confidence = evidence.ConfidenceMedium
		return rec
	}
	rec.Grants = parseDarwinACLListing(string(raw))
	rec.HasExtendedACL = len(rec.Grants) > 0
	classifyACLBoundary(&rec)
	return rec
}

func parseDarwinACLListing(raw string) []ACLGrant {
	out := []ACLGrant{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	first := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if first {
			first = false
			continue
		}
		if line == "" {
			continue
		}
		// Typical macOS ACL entry: 0: user:alice allow read,write,delete inherited
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimSpace(line[:colon])); err != nil {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line[colon+1:]))
		if len(fields) < 3 {
			continue
		}
		principal := fields[0]
		accessIndex := -1
		for i := 1; i < len(fields); i++ {
			v := strings.ToLower(strings.TrimSpace(fields[i]))
			if v == "allow" || v == "deny" {
				accessIndex = i
				break
			}
		}
		if accessIndex < 0 || accessIndex+1 >= len(fields) {
			continue
		}
		access := strings.ToUpper(fields[accessIndex])
		rightsText := strings.Join(fields[accessIndex+1:], " ")
		inherited := strings.Contains(strings.ToLower(rightsText), "inherited")
		rightsText = strings.ReplaceAll(rightsText, " inherited", "")
		rightsText = strings.ReplaceAll(rightsText, ",", " ")
		rights := []string{}
		for _, r := range strings.Fields(rightsText) {
			r = strings.ToUpper(strings.TrimSpace(r))
			if r != "" {
				rights = append(rights, r)
			}
		}
		lowPrincipal := strings.ToLower(principal)
		class := "NAMED_PRINCIPAL"
		if strings.HasPrefix(lowPrincipal, "user:") {
			class = "NAMED_USER"
		} else if strings.HasPrefix(lowPrincipal, "group:") {
			class = "NAMED_GROUP"
		}
		broad := strings.Contains(lowPrincipal, "everyone") || strings.Contains(lowPrincipal, "guest") || strings.Contains(lowPrincipal, "users")
		trusted := strings.Contains(lowPrincipal, "user:root") || strings.Contains(lowPrincipal, "group:wheel") || strings.Contains(lowPrincipal, "group:admin") || strings.Contains(lowPrincipal, "_securityagent")
		writeLike := darwinACLWriteLike(rights)
		controlLike := containsString(rights, "WRITESECURITY") || containsString(rights, "CHOWN") || containsString(rights, "WRITEOWNER")
		out = append(out, ACLGrant{Principal: principal, PrincipalClass: class, Access: access, Rights: rights, Inherited: inherited, Effective: true, Broad: broad, Trusted: trusted, WriteLike: writeLike, ControlLike: controlLike})
	}
	return out
}

func darwinACLWriteLike(rights []string) bool {
	for _, r := range rights {
		switch strings.ToUpper(strings.TrimSpace(r)) {
		case "WRITE", "ADD_FILE", "ADD_SUBDIRECTORY", "DELETE", "DELETE_CHILD", "WRITEATTR", "WRITEEXTATTR", "APPEND", "FILE_INHERIT", "DIRECTORY_INHERIT":
			return true
		}
	}
	return false
}
