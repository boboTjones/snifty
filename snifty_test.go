package snifty

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket/pcap"
)

func genTraffic() {
	data, err := ioutil.ReadFile("testurls.txt")
	if err != nil {
		log.Fatal(err)
	}
	urls := bytes.Split(data, []byte("\n"))
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	done := make(chan bool)
	go func() {
		// XX ToDo(erin): adjust
		time.Sleep(10 * time.Second)
		done <- true
	}()
	for {
		select {
		case <-done:
			fmt.Println("Stopping HTTP traffic.")
			return
		case t := <-ticker.C:
			fmt.Println(t)
			ri := rand.Intn(len(urls))
			fmt.Println(ri)
			url := urls[ri]
			_, err := http.Get(string(url))
			if err != nil {
				panic(err)
			}
		}
	}
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
	hs := NewHttpSniffer("en0", 1600, 20, pcap.BlockForever, false)
	fmt.Printf("Sniffing HTTP traffic. Greedy? %v\n", hs.Greedy)
	defer hs.Close()
	go hs.Listen()
	for {
		go genTraffic()
		fmt.Printf("TEST OUTPUT: %v\n", <-hs.Out)
	}
}
