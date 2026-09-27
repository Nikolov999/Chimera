//go:build linux

package network

import "testing"

func TestDecodeProcAddresses(t *testing.T) {
	got, err := decodeProcAddress("0100007F", "IPV4")
	if err != nil || got != "127.0.0.1" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	got, err = decodeProcAddress("00000000000000000000000001000000", "IPV6")
	if err != nil || got != "::1" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}
