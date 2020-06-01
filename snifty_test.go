package snifty

import (
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func genTraff() {
	cmd := exec.Command("curl", "http://www.google.com/")
	cmd.Run()
}

func MakeNewHttpSniff() *HttpSniff {
	timeout, err := time.ParseDuration("10us")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	return &HttpSniff{
		IFace:   "en0",
		SnapLen: 1024,
		Max:     100,
		Timeout: timeout,
	}
}

func TestNewHttpSniff(t *testing.T) {
	want := MakeNewHttpSniff()
	timeout, err := time.ParseDuration("10us")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	if got := NewHttpSniff("en0", 1024, 100, timeout); !cmp.Equal(got, want) {
		t.Errorf("Make new HttpSniff\n\tWanted: %T; Got: %T\n ", want, got)
	}
}

func TestListen(t *testing.T) {
	// XX ToDo(erin): currently mocked up to pass. Will change when
	// I figure out how I want this to work
	want := "dammit"
	hs := MakeNewHttpSniff()
	if got := hs.Listen(); got != want {
		t.Errorf("sniff test; got: %q; want: %q", got, want)
	}
}
