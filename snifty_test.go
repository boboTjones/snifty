package snifty

import (
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket/pcap"
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
		SnapLen: 1600,
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
	if got := NewHttpSniffer("en0", 1600, 10, timeout, false); !cmp.Equal(got, want) {
		t.Errorf("Make new HttpSniff\n\tWanted: %v; Got: %T\n ", want, got)
	}
	//want.Close()
}

func TestListen(t *testing.T) {
	// XX ToDo(erin): this passes but it should make more noise. Fix it.
	//hs := MakeNewHttpSniffer()
	hs := NewHttpSniffer("en0", 1600, 20, pcap.BlockForever, false)
	fmt.Printf("Sniffing HTTP traffic. Greedy? %v\n", hs.Greedy)
	defer hs.Close()
	go hs.Listen()
	for {
		go genTraffic()
		fmt.Printf("TEST OUTPUT: %v\n", <-hs.Out)
	}
}
