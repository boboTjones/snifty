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
)

var hs *HttpSniffer
var results *Results

func genTraffic(done chan bool) {
	data, err := ioutil.ReadFile("testurls.txt")
	if err != nil {
		log.Fatal(err)
	}
	urls := bytes.Split(data, []byte("\n"))
	timeout := time.NewTimer(10 * time.Second)
	fmt.Println("Generating HTTP traffic")

	for {
		select {
		case <-timeout.C:
			fmt.Println("Stopping HTTP traffic")
			done <- true
			return
		default:
			ri := rand.Intn(len(urls) - 1)
			url := urls[ri]
			fmt.Println("fetching ", string(url))
			_, err := http.Get(string(url))
			if err != nil {
				fmt.Println(err)
			}
			time.Sleep(time.Second)
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
		Timeout: timeout,
		Greedy:  false,
	}
}

func TestNewHttpSniffer(t *testing.T) {
	// This is always going to fail.
	want := MakeNewHttpSniffer()
	timeout, err := time.ParseDuration("10us")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if got := NewHttpSniffer("en0", 1600, timeout, false); !cmp.Equal(got, want) {
		t.Errorf("Make new HttpSniff\n\tWanted: %v; Got: %v\n ", want, got)
	}
}

func TestListen(t *testing.T) {
	done := make(chan bool)
	// XX ToDo(erin): this passes but it should make more noise. Fix it.
	timeout, err := time.ParseDuration("10us")
	if err != nil {
		t.Fatalf("%v", err)
	}
	hs := NewHttpSniffer("en0", 1600, timeout, false)
	results := &Results{Counter: 0}
	t.Logf("Sniffing HTTP traffic. Greedy? %v\n", hs.Greedy)
	defer hs.Close()
	go hs.Listen()
	// generate 10 requests at 1 second intervals
	go genTraffic(done)
	for {
		results.AddResult(<-hs.Out)
	}
}

func TestAddResult(t *testing.T) {
	results := &Results{Counter: 0}
	raw := []byte{71, 69, 84, 32, 47, 99, 111, 110, 116, 101, 110, 116, 47, 110, 121, 117, 47, 101, 110, 47, 97, 99, 97, 100, 101, 109, 105, 99, 115, 47, 115, 99, 104, 111, 108, 97, 114, 108, 121, 45, 115, 116, 114, 101, 110, 103, 116, 104, 115, 46, 104, 116, 109, 108, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58, 32, 119, 119, 119, 46, 110, 121, 117, 46, 101, 100, 117, 13, 10, 85, 115, 101, 114, 45, 65, 103, 101, 110, 116, 58, 32, 71, 111, 45, 104, 116, 116, 112, 45, 99, 108, 105, 101, 110, 116, 47, 49, 46, 49, 13, 10, 65, 99, 99, 101, 112, 116, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105, 112, 13, 10, 13, 10}
	hp := HttpPacket{Section: "www.nyu.edu/content",
		DstPort: []byte{80},
		Raw:     raw,
	}
	want := Result{Section: hp.Section, Count: 1}
	results.AddResult(hp)
	if got := results.Results[0]; !cmp.Equal(got, want) {
		t.Errorf("Adding result\n\tWanted: %v; Got: %v\n", want, got)
	}
}

func TestDump(t *testing.T) {
	done := make(chan bool)
	results := &Results{Counter: 0}
	timeout, err := time.ParseDuration("10us")
	if err != nil {
		t.Fatalf("%v", err)
	}
	hs := NewHttpSniffer("en0", 1600, timeout, false)
	defer hs.Close()
	go hs.Listen()
	// generate 10 requests at 1 second intervals
	go genTraffic(done)
	//XX ToDo somehow adding this channel means nothing gets added.
	for !<-done {
		results.AddResult(<-hs.Out)
	}
	want := 10
	if got := len(results.Results); got != want {
		t.Errorf("Test dump failed.\n\tWanted: %d; got %d\n", want, got)
	}
}

func TestSample(t *testing.T) {
	done := make(chan bool)
	results := &Results{Counter: 0}
	timeout, err := time.ParseDuration("10us")
	if err != nil {
		t.Fatalf("%v", err)
	}
	hs := NewHttpSniffer("en0", 1600, timeout, false)
	defer hs.Close()
	go hs.Listen()
	results.Sample()
	// generate 10 requests at 1 second intervals
	go genTraffic(done)
	//XX ToDo somehow adding this channel means nothing gets added.
	for {
		select {
		case packet := <-hs.Out:
			results.AddResult(packet)
			//fmt.Println(results.Results)
		case <-done:
			break
		}
	}
	results.Sample()
	want := 10
	if got := len(results.Samples); got != want {
		t.Errorf("Test sample failed.\n\tWanted: %d; got %d\n", want, got)
	}
}
