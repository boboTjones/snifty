package snifty

import (
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func genTraffic() {
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
		Max:     10,
		Timeout: timeout,
		Greedy:  true,
	}
}

func TestNewHttpSniff(t *testing.T) {
	want := MakeNewHttpSniff()
	timeout, err := time.ParseDuration("10us")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	if got := NewHttpSniffer("en0", 1024, 10, timeout, true); !cmp.Equal(got, want) {
		t.Errorf("Make new HttpSniff\n\tWanted: %T; Got: %T\n ", want, got)
	}
}

func TestListen(t *testing.T) {
	// XX ToDo(erin): this fails. Fix it.
	hs := MakeNewHttpSniffer()
	defer hs.Close()
	for {
		go hs.Listen()
		go genTraffic()
	}
}
