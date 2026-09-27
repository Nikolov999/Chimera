//go:build linux

package accounts

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Nikolov999/chimera/internal/evidence"
)

func TestCollectLinuxAuthenticationParsesPAMAndLoginPolicy(t *testing.T) {
	root := t.TempDir()
	pamDir := filepath.Join(root, "pam.d")
	secDir := filepath.Join(root, "security")
	if err := os.MkdirAll(pamDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secDir, 0755); err != nil {
		t.Fatal(err)
	}
	mustWrite := func(path, data string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(pamDir, "common-auth"), "auth required pam_faillock.so preauth deny=4 unlock_time=900\nauth sufficient pam_unix.so try_first_pass\nauth required pam_deny.so\n", 0644)
	mustWrite(filepath.Join(pamDir, "common-password"), "password requisite pam_pwquality.so retry=3 minlen=14\npassword required pam_pwhistory.so remember=8 use_authtok\npassword sufficient pam_unix.so yescrypt\n", 0644)
	mustWrite(filepath.Join(root, "login.defs"), "PASS_MAX_DAYS 180\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 14\nENCRYPT_METHOD YESCRYPT\n", 0644)
	mustWrite(filepath.Join(secDir, "faillock.conf"), "deny = 4\nunlock_time = 900\neven_deny_root\n", 0644)
	mustWrite(filepath.Join(secDir, "pwquality.conf"), "minlen = 14\nminclass = 3\nretry = 3\n", 0644)
	mustWrite(filepath.Join(secDir, "pwhistory.conf"), "remember = 8\n", 0644)

	got := collectLinuxAuthentication(context.Background(), root)
	if got.State != evidence.StateObserved {
		t.Fatalf("state=%s reason=%s", got.State, got.Reason)
	}
	if got.Summary.PAMRules != 6 || got.Summary.LockoutRules != 1 || got.Summary.QualityRules != 1 || got.Summary.HistoryRules != 1 {
		t.Fatalf("unexpected summary: %#v", got.Summary)
	}
	if got.Tuning.FaillockDeny != 4 || got.Tuning.FaillockUnlockTime != 900 || !got.Tuning.EvenDenyRoot {
		t.Fatalf("unexpected faillock tuning: %#v", got.Tuning)
	}
	if got.Tuning.PwqualityMinLen != 14 || got.Tuning.PasswordRemember != 8 {
		t.Fatalf("unexpected password tuning: %#v", got.Tuning)
	}
	if got.LoginPolicy.MaxDays != 180 || got.LoginPolicy.MinDays != 1 || got.LoginPolicy.WarnAge != 14 || got.LoginPolicy.EncryptMethod != "YESCRYPT" {
		t.Fatalf("unexpected login policy: %#v", got.LoginPolicy)
	}
	if err := validateLinuxAuthPosture("linux", got); err != nil {
		t.Fatal(err)
	}
}

func TestParsePAMFileCapturesOnlySecurityMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test")
	if err := os.WriteFile(path, []byte("auth required pam_unix.so nullok\npassword required pam_unix.so sha512 remember=5\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, rules, err := parsePAMFile(context.Background(), path, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Parsed || len(rules) != 2 {
		t.Fatalf("cfg=%#v rules=%#v", cfg, rules)
	}
	if !rules[0].NullOK {
		t.Fatal("nullok metadata not captured")
	}
	if rules[1].Hash != "SHA512" || rules[1].Remember != 5 {
		t.Fatalf("password metadata not normalized: %#v", rules[1])
	}
}
