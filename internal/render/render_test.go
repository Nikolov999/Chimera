package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Nikolov999/chimera/internal/cli"
)

func TestJSONSuppressesBanner(t *testing.T) {
	var b bytes.Buffer
	Banner(&b, cli.Options{JSON: true})
	if b.Len() != 0 {
		t.Fatalf("machine mode banner leaked: %q", b.String())
	}
}

func TestPlainBannerHasNoANSI(t *testing.T) {
	var b bytes.Buffer
	Banner(&b, cli.Options{Plain: true})
	if strings.Contains(b.String(), "\x1b[") {
		t.Fatal("plain banner contains ANSI")
	}
	if !strings.Contains(b.String(), "IRONCLAD") {
		t.Fatal("missing product identity")
	}
}

func TestJSONUsesCompactMachineEncoding(t *testing.T) {
	var b bytes.Buffer
	data := map[string]any{
		"outer": map[string]any{"alpha": 1, "beta": []string{"x", "y"}},
	}
	if err := JSON(&b, data); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "\n  ") || strings.Contains(out, "\n    ") {
		t.Fatalf("machine JSON unexpectedly contains pretty-print indentation: %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("machine JSON should retain one streaming newline: %q", out)
	}
}
