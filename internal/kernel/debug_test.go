package kernel

import "testing"

func TestDebugBootArguments(t *testing.T) {
	got := debugBootArguments("-v debug=0x144 keepsyms=1 foo=bar kdp_match_name=en0")
	if len(got) != 3 || got[0] != "debug=0x144" || got[1] != "keepsyms=1" || got[2] != "kdp_match_name=en0" {
		t.Fatalf("got %v", got)
	}
}

func TestParseBCDBooleanElement(t *testing.T) {
	text := "identifier {current}\ndebug Yes\nbootdebug No\n"
	if v, ok := parseBCDBooleanElement(text, "debug"); !ok || !v {
		t.Fatalf("debug parse = %v,%v", v, ok)
	}
	if v, ok := parseBCDBooleanElement(text, "bootdebug"); !ok || v {
		t.Fatalf("bootdebug parse = %v,%v", v, ok)
	}
	if _, ok := parseBCDBooleanElement(text, "missing"); ok {
		t.Fatal("missing element unexpectedly found")
	}
}
