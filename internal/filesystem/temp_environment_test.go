package filesystem

import (
	"reflect"
	"testing"
)

func TestSplitWindowsTempPathValueKeepsLegitimateSpaces(t *testing.T) {
	got := splitWindowsTempPathValue(`C:\Program Files\Example Temp`)
	want := []string{`C:\Program Files\Example Temp`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitWindowsTempPathValueSeparatesMalformedCombinedPaths(t *testing.T) {
	got := splitWindowsTempPathValue(`C:\Users\demo\AppData\Local\Temp C:\Windows\Temp`)
	want := []string{`C:\Users\demo\AppData\Local\Temp`, `C:\Windows\Temp`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestSplitWindowsTempPathValueHandlesQuotesAndSemicolons(t *testing.T) {
	got := splitWindowsTempPathValue(`"C:\Program Files\Temp";"C:\Windows\Temp"`)
	want := []string{`C:\Program Files\Temp`, `C:\Windows\Temp`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}
