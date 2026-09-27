package productnorm

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// CompareVersions compares two versions using the candidate's ecosystem
// semantics. It returns -1, 0, +1. Unsupported or unsafe inputs return an
// error rather than falling back to lexical ordering.
func CompareVersions(ecosystem, a, b string) (int, error) {
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if !versionPresent(a) || !versionPresent(b) {
		return 0, fmt.Errorf("version is absent or unknown")
	}
	switch ecosystem {
	case "dpkg":
		return compareDebian(a, b), nil
	case "rpm":
		return compareRPM(a, b), nil
	case "apk", "pacman", "native-package", "snap", "flatpak", "windows", "appx", "macos":
		return compareTokenized(a, b), nil
	case "maven":
		return compareMaven(a, b), nil
	default:
		if strings.HasPrefix(ecosystem, "runtime:") || ecosystem == "runtime" {
			return compareTokenized(a, b), nil
		}
		return 0, fmt.Errorf("unsupported version ecosystem %q", ecosystem)
	}
}

func IsComparable(ecosystem, version string) bool {
	if !versionPresent(version) {
		return false
	}
	_, err := CompareVersions(ecosystem, version, version)
	return err == nil
}

func versionScheme(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "dpkg":
		return "debian"
	case "rpm":
		return "rpm"
	case "maven":
		return "maven"
	case "apk":
		return "apk-tokenized"
	case "pacman":
		return "pacman-tokenized"
	case "native-package":
		return "native-tokenized"
	case "snap":
		return "snap-tokenized"
	case "flatpak":
		return "flatpak-tokenized"
	case "windows", "appx":
		return "windows-tokenized"
	case "macos":
		return "macos-tokenized"
	default:
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ecosystem)), "runtime:") || strings.EqualFold(ecosystem, "runtime") {
			return "runtime-tokenized"
		}
		return "unsupported"
	}
}

func versionPresent(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	return v != "" && v != "unknown" && v != "n/a" && v != "unavailable"
}

// Debian comparison follows dpkg's epoch:upstream-revision ordering model,
// including the special ordering of '~'.
func compareDebian(a, b string) int {
	ea, ua, ra := splitDebian(a)
	eb, ub, rb := splitDebian(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := debPartCompare(ua, ub); c != 0 {
		return c
	}
	return debPartCompare(ra, rb)
}

func splitDebian(v string) (int64, string, string) {
	epoch := int64(0)
	rest := v
	if i := strings.Index(rest, ":"); i > 0 {
		if n, err := strconv.ParseInt(rest[:i], 10, 64); err == nil {
			epoch, rest = n, rest[i+1:]
		}
	}
	upstream, revision := rest, "0"
	if i := strings.LastIndex(rest, "-"); i >= 0 {
		upstream, revision = rest[:i], rest[i+1:]
	}
	return epoch, upstream, revision
}

func debPartCompare(a, b string) int {
	ia, ib := 0, 0
	for ia < len(a) || ib < len(b) {
		for (ia < len(a) && !isASCIIDigit(a[ia])) || (ib < len(b) && !isASCIIDigit(b[ib])) {
			oa, ob := debOrder(byteAt(a, ia)), debOrder(byteAt(b, ib))
			if oa != ob {
				if oa < ob {
					return -1
				}
				return 1
			}
			if ia < len(a) {
				ia++
			}
			if ib < len(b) {
				ib++
			}
		}
		for ia < len(a) && a[ia] == '0' {
			ia++
		}
		for ib < len(b) && b[ib] == '0' {
			ib++
		}
		ja, jb := ia, ib
		for ja < len(a) && isASCIIDigit(a[ja]) {
			ja++
		}
		for jb < len(b) && isASCIIDigit(b[jb]) {
			jb++
		}
		la, lb := ja-ia, jb-ib
		if la != lb {
			if la < lb {
				return -1
			}
			return 1
		}
		if la > 0 {
			if c := strings.Compare(a[ia:ja], b[ib:jb]); c != 0 {
				return c
			}
		}
		ia, ib = ja, jb
	}
	return 0
}

func debOrder(c byte) int {
	if c == '~' {
		return -1
	}
	if c == 0 {
		return 0
	}
	if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
		return int(c)
	}
	return int(c) + 256
}

func byteAt(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}

func isASCIIDigit(c byte) bool { return c >= '0' && c <= '9' }

// compareRPM implements the core rpmvercmp behavior: separator skipping,
// numeric-vs-alpha segments, tilde pre-release ordering, and caret post-release
// ordering. Epoch handling is accepted when present as "epoch:version".
func compareRPM(a, b string) int {
	ea, va := splitEpoch(a)
	eb, vb := splitEpoch(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	return rpmVerCmp(va, vb)
}

func splitEpoch(v string) (int64, string) {
	if i := strings.Index(v, ":"); i > 0 {
		if n, err := strconv.ParseInt(v[:i], 10, 64); err == nil {
			return n, v[i+1:]
		}
	}
	return 0, v
}

func rpmVerCmp(a, b string) int {
	ia, ib := 0, 0
	for ia < len(a) || ib < len(b) {
		for ia < len(a) && !isAlphaNum(a[ia]) && a[ia] != '~' && a[ia] != '^' {
			ia++
		}
		for ib < len(b) && !isAlphaNum(b[ib]) && b[ib] != '~' && b[ib] != '^' {
			ib++
		}
		if ia < len(a) && a[ia] == '~' || ib < len(b) && b[ib] == '~' {
			if ia >= len(a) || a[ia] != '~' {
				return 1
			}
			if ib >= len(b) || b[ib] != '~' {
				return -1
			}
			ia++
			ib++
			continue
		}
		if ia < len(a) && a[ia] == '^' || ib < len(b) && b[ib] == '^' {
			if ia >= len(a) {
				return -1
			}
			if ib >= len(b) {
				return 1
			}
			if a[ia] != '^' {
				return 1
			}
			if b[ib] != '^' {
				return -1
			}
			ia++
			ib++
			continue
		}
		if ia >= len(a) || ib >= len(b) {
			break
		}
		na, nb := isASCIIDigit(a[ia]), isASCIIDigit(b[ib])
		ja, jb := ia, ib
		if na {
			for ja < len(a) && isASCIIDigit(a[ja]) {
				ja++
			}
		} else {
			for ja < len(a) && isASCIIAlpha(a[ja]) {
				ja++
			}
		}
		if nb {
			for jb < len(b) && isASCIIDigit(b[jb]) {
				jb++
			}
		} else {
			for jb < len(b) && isASCIIAlpha(b[jb]) {
				jb++
			}
		}
		if na != nb {
			if na {
				return 1
			}
			return -1
		}
		sa, sb := a[ia:ja], b[ib:jb]
		if na {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if sa == "" {
				sa = "0"
			}
			if sb == "" {
				sb = "0"
			}
			if len(sa) != len(sb) {
				if len(sa) < len(sb) {
					return -1
				}
				return 1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
		ia, ib = ja, jb
	}
	for ia < len(a) && !isAlphaNum(a[ia]) {
		ia++
	}
	for ib < len(b) && !isAlphaNum(b[ib]) {
		ib++
	}
	if ia == len(a) && ib == len(b) {
		return 0
	}
	if ia == len(a) {
		return -1
	}
	return 1
}

func isAlphaNum(c byte) bool   { return isASCIIDigit(c) || isASCIIAlpha(c) }
func isASCIIAlpha(c byte) bool { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') }

type vtok struct {
	numeric bool
	text    string
	num     string
}

func tokenizeVersion(v string) []vtok {
	v = strings.TrimSpace(strings.ToLower(strings.TrimPrefix(strings.TrimSpace(v), "v")))
	out := make([]vtok, 0, 8)
	var cur strings.Builder
	mode := byte(0)
	flush := func() {
		if cur.Len() == 0 {
			return
		}
		s := cur.String()
		out = append(out, vtok{numeric: mode == 'n', text: s, num: strings.TrimLeft(s, "0")})
		if out[len(out)-1].numeric && out[len(out)-1].num == "" {
			out[len(out)-1].num = "0"
		}
		cur.Reset()
	}
	for _, r := range v {
		var m byte
		if unicode.IsDigit(r) {
			m = 'n'
		} else if unicode.IsLetter(r) {
			m = 'a'
		} else {
			flush()
			mode = 0
			continue
		}
		if mode != 0 && mode != m {
			flush()
		}
		mode = m
		cur.WriteRune(r)
	}
	flush()
	return out
}

func compareTokenized(a, b string) int {
	aa, bb := tokenizeVersion(a), tokenizeVersion(b)
	n := len(aa)
	if len(bb) > n {
		n = len(bb)
	}
	for i := 0; i < n; i++ {
		if i >= len(aa) {
			return remainingTokenOrder(bb[i:]) * -1
		}
		if i >= len(bb) {
			return remainingTokenOrder(aa[i:])
		}
		x, y := aa[i], bb[i]
		if x.numeric && y.numeric {
			if len(x.num) != len(y.num) {
				if len(x.num) < len(y.num) {
					return -1
				}
				return 1
			}
			if c := strings.Compare(x.num, y.num); c != 0 {
				return c
			}
			continue
		}
		if x.numeric != y.numeric {
			if x.numeric {
				return 1
			}
			return -1
		}
		qx, qy := qualifierRank(x.text), qualifierRank(y.text)
		if qx != qy {
			if qx < qy {
				return -1
			}
			return 1
		}
		if c := strings.Compare(x.text, y.text); c != 0 {
			return c
		}
	}
	return 0
}

func remainingTokenOrder(tokens []vtok) int {
	for _, t := range tokens {
		if t.numeric {
			if t.num != "0" {
				return 1
			}
			continue
		}
		if qualifierRank(t.text) < qualifierRank("") {
			return -1
		}
		if t.text != "" {
			return 1
		}
	}
	return 0
}

func compareMaven(a, b string) int { return compareTokenized(a, b) }

func qualifierRank(q string) int {
	switch strings.ToLower(q) {
	case "alpha", "a":
		return -50
	case "beta", "b":
		return -40
	case "milestone", "m":
		return -30
	case "rc", "cr":
		return -20
	case "snapshot":
		return -10
	case "", "ga", "final", "release":
		return 0
	case "sp":
		return 10
	default:
		return 5
	}
}
