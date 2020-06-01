package snifty

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func MakeNewHttpSniff() *HttpSniff {
	timeout, err := time.ParseDuration("1us")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	return &HttpSniff{
		IFace:   "en0",
		SnapLen: 1024,
		Max:     10,
		Timeout: timeout,
	}
}

func TestHw(t *testing.T) {
	want := "Hi, mom!"
	if got := Hw(); got != want {
		t.Errorf("hello mom test; got: %q; want: %q", got, want)
	}
}

func TestNewHttpSniff(t *testing.T) {
	want := MakeNewHttpSniff()
	timeout, err := time.ParseDuration("1us")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	if got := NewHttpSniff("en0", 1024, 10, timeout); !cmp.Equal(got, want) {
		t.Errorf("Make new HttpSniff\n\tWanted: %T; Got: %T\n ", want, got)
	}
}

func TestSniff(t *testing.T) {
	want := "dammit"
	hs := MakeNewHttpSniff()
	if got := hs.Sniff(); got != want {
		t.Errorf("sniff test; got: %q; want: %q", got, want)
	}
}
