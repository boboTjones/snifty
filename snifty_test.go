package snifty

import (
	"fmt"
	"testing"
	"time"
)

func TestHw(t *testing.T) {
	want := "Hi, mom!"
	if got := Hw(); got != want {
		t.Errorf("hello mom test; got: %q; want: %q", got, want)
	}
}

func TestSniff(t *testing.T) {
	want := "foo"
	timeout, err := time.ParseDuration("1us")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	if got := Sniff("en0", 80, timeout); got != want {
		t.Errorf("sniff test; got: %q; want: %q", got, want)
	}
}
