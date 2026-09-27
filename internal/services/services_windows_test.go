//go:build windows

package services

import "testing"

func TestFix18DecodeSecurityEnvelopeArray(t *testing.T) {
	raw := []byte(`[{"name":"SvcA","security":{"service_acl_state":"OBSERVED","account_admin_state":"NO","registry_state":"OBSERVED","registry_acl":{"state":"OBSERVED"},"executable_acl":{"state":"OBSERVED"},"executable_directory_acl":{"state":"OBSERVED"},"service_dll_acl":{"state":"NOT_APPLICABLE"},"service_dll_directory_acl":{"state":"NOT_APPLICABLE"},"failure_executable_acl":{"state":"NOT_APPLICABLE"},"failure_executable_directory_acl":{"state":"NOT_APPLICABLE"}}}]`)
	got, err := decodeWindowsServiceSecurity(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "SvcA" || got[0].Security.RegistryState != "OBSERVED" {
		t.Fatalf("unexpected decoded security envelope: %#v", got)
	}
}

func TestFix18ProviderDetailIsBounded(t *testing.T) {
	long := make([]byte, 1000)
	for i := range long {
		long[i] = 'x'
	}
	got := boundedServiceProviderText(string(long), 64)
	if len(got) > 67 || got[len(got)-3:] != "..." {
		t.Fatalf("provider detail was not bounded: %q", got)
	}
}
