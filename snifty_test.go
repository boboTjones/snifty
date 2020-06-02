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

func MakeNewHttpSniffer() *HttpSniffer {
	timeout, err := time.ParseDuration("1us")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	return &HttpSniffer{
		IFace:   "en0",
		SnapLen: 1024,
		Max:     10,
		Timeout: timeout,
		Greedy:  false,
	}
}

func TestNewHttpSniffer(t *testing.T) {
	// This is always going to fail.
	want := MakeNewHttpSniffer()
	timeout, err := time.ParseDuration("1us")
	if err != nil {
		fmt.Errorf("%v", err)
	}
	if got := NewHttpSniffer("en0", 1024, 10, timeout, false); !cmp.Equal(got, want) {
		t.Errorf("Make new HttpSniff\n\tWanted: %v; Got: %T\n ", want, got)
	}
	//want.Close()
}

func TestListen(t *testing.T) {
	// XX ToDo(erin): this passes but it should make more noise. Fix it.
	hs := MakeNewHttpSniffer()
	defer hs.Close()
	for {
		go hs.Listen()
		//go genTraffic()
		fmt.Println(<-hs.Out)
	}
}
