// Create a simple console program that monitors HTTP traffic on your machine:
// 1. Sniff network traffic to detect HTTP activity.
// 2. Every 10s, display in the console the sections of the [web site with the most
//    hits] (a section is defined as being what's before the second '/' in a URL. i.e.
//    the section for "http://my.site.com/pages/create' is "http://my.site.com/pages"),
//    as well as interesting summary statistics on the traffic as a whole. Determine
//   which URL gets the most hits, extract the "section" of the path and display the
//   number of hits per "section"
// 3. Make sure a user can keep the console app running and monitor traffic on their machine.
// 4. Whenever total traffic for the past 2 minutes exceeds a certain number on average,
//    add a message saying that “High traffic generated an alert - hits = {value}, triggered at {time}”.
// 5. Whenever the total traffic drops again below that value on average for the past 2
//    minutes, add another message detailing when the alert recovered.
//    2 minute window for avg rate
//    every second sample the counter to see how much it has increased
//    array of all samples collected up to 120 elements (ring buffer)
//    average the last seven samples in the array
// 6. Make sure all messages showing when alerting thresholds are crossed remain visible
//    on the page for historical reasons.
// 7. Write a test for the alerting logic.
// 8. Explain how you’d improve on this application design.

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

func init() {
	flag.BoolVar(&greedy, "g", false, "Run SniftySniff in greedy mode")
	flag.IntVar(&max, "m", 0, "Specific the number of packets to collect")
	flag.BoolVar(&version, "v", false, "Print version and exit")
}

func main() {
	flag.Parse()
	if version {
		fmt.Println("Snifty Sniff version 0.1. We can only go up from here.")
		os.Exit(0)
	}
	results := &snifty.Results{Counter: 0}
	hs := snifty.NewHttpSniffer("en0", 1600, max, pcap.BlockForever, greedy)
	fmt.Printf("Snifty Sniff, the HTTP sniffer that is nifty.\nGreedy? %v\n", hs.Greedy)
	defer hs.Close()
	go hs.Listen()
	go results.Dump()
	go results.Sample()
	for {
		results.AddResult(<-hs.Out)
	}
}
