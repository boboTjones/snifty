// Create a simple console program that monitors HTTP traffic on your machine:
// [x] Sniff network traffic to detect HTTP activity.
// [x] Every 10s, display in the console the sections of the [web site with the most
//    hits] (a section is defined as being what's before the second '/' in a URL. i.e.
//    the section for "http://my.site.com/pages/create' is "http://my.site.com/pages"),
//    as well as interesting summary statistics on the traffic as a whole. Determine
//   which URL gets the most hits, extract the "section" of the path and display the
//   number of hits per "section"
// [x] Make sure a user can keep the console app running and monitor traffic on their machine.
// [ ] Whenever total traffic for the past 2 minutes exceeds a certain number on average,
//    add a message saying that “High traffic generated an alert - hits = {value}, triggered at {time}”.
// [ ] Whenever the total traffic drops again below that value on average for the past 2
//    minutes, add another message detailing when the alert recovered.
//    2 minute window for avg rate
//    every second sample the counter to see how much it has increased
//    array of all samples collected up to 120 elements (ring buffer)
//    average the last seven samples in the array
// [ ] Make sure all messages showing when alerting thresholds are crossed remain visible
//    on the page for historical reasons.
// [ ] Write a test for the alerting logic.
// [ ] Explain how you’d improve on this application design. (todo move notes to readme)

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/bobotjones/snifty"
	"github.com/google/gopacket/pcap"
)

var greedy, version bool
var max int
var config string

type Config struct {
	Greedy int `json:"greedy"`
	Max    int `json:"max"`
	// some other things, like maybe specific host?
}

func Stopper(done chan bool) <-chan string {
	fmt.Println("Tap any key to exit.")
	s := make(chan string)
	defer close(s)
	go func() {
		for {
			select {
			case <-s:
				done <- true
			default:
				fmt.Scanf("%s", &s)
			}
		}
	}()
	return s
}

func init() {
	flag.BoolVar(&greedy, "g", false, "Run SniftySniff in greedy mode")
	flag.BoolVar(&version, "v", false, "Print version and exit")
	flag.StringVar(&config, "c", config, "Specify a config file")
}

func main() {
	flag.Parse()
	if version {
		fmt.Println("Snifty Sniff version 0.1. We can only go up from here.")
		os.Exit(0)
	}
	results := &snifty.Results{Counter: 0, Threshold: 12}
	hs := snifty.NewHttpSniffer("en0", 1600, pcap.BlockForever, greedy)
	fmt.Printf("Snifty Sniff, the HTTP sniffer that is nifty.\nGreedy? %v\n", hs.Greedy)
	defer hs.Close()
	go hs.Listen()
	done := make(chan bool)
	results.Run(done)

	complete := false
	for !complete {
		select {
		case packet := <-hs.Out:
			results.AddResult(packet)
		case <-done:
			complete = true
		}
	}
}
