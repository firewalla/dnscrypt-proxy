package main

import (
	"runtime"
	"testing"
)

func TestDialerControlForMark(t *testing.T) {
	control := dialerControlForMark(newFWMarkResolverWithReader(newFakeKeyReader(nil), "dnscrypt:markkey"))
	if runtime.GOOS == "linux" {
		if control == nil {
			t.Fatal("expected a Control callback for fwmark on linux")
		}
	} else if control != nil {
		t.Fatal("expected no Control callback for fwmark outside linux")
	}
}
