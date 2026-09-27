//go:build linux

package accounts

import (
	"context"
	"strings"
	"testing"
)

func TestParseLinuxShadowPasswordStatusDerivesOnlyState(t *testing.T) {
	input := strings.Join([]string{
		"alice:$y$j9T$opaquehash:20000:0:99999:7:::",
		"bob::20001:0:99999:7:::",
		"svc:!:20002:0:99999:7:::",
		"daemon:*:20003:0:99999:7:::",
	}, "\n")

	got, err := parseLinuxShadowPasswordStatus(context.Background(), strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if got["alice"].state != "PASSWORD_SET" {
		t.Fatalf("alice state=%q", got["alice"].state)
	}
	if got["bob"].state != "EMPTY" {
		t.Fatalf("bob state=%q", got["bob"].state)
	}
	if got["svc"].state != "LOCKED" || got["daemon"].state != "LOCKED" {
		t.Fatalf("locked states: svc=%q daemon=%q", got["svc"].state, got["daemon"].state)
	}
	for name, st := range got {
		if strings.Contains(st.source, "opaquehash") || strings.Contains(st.lastChange, "opaquehash") || strings.Contains(st.state, "opaquehash") {
			t.Fatalf("credential material retained for %s: %#v", name, st)
		}
	}
}

func TestDeriveShadowPasswordState(t *testing.T) {
	cases := map[string]string{
		"":              "EMPTY",
		"!":             "LOCKED",
		"!!":            "LOCKED",
		"*":             "LOCKED",
		"*LK*":          "LOCKED",
		"$6$abc$opaque": "PASSWORD_SET",
	}
	for input, want := range cases {
		if got := deriveShadowPasswordState(input); got != want {
			t.Fatalf("deriveShadowPasswordState(%q)=%q want %q", input, got, want)
		}
	}
}
