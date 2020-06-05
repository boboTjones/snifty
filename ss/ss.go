// [?] Whenever total traffic for the past 2 minutes exceeds a certain number on average,
//    add a message saying that “High traffic generated an alert - hits = {value}, triggered at {time}”.
// [] Whenever the total traffic drops again below that value on average for the past 2
//    minutes, add another message detailing when the alert recovered.
//    2 minute window for avg rate
//    every second sample the counter to see how much it has increased
//    array of all samples collected up to 120 elements (ring buffer)
//    average the last seven samples in the array
// [] take a config file in JSON format, parse and use it to populate alerts, counts, etcs
// [ ] Write a test for the alerting logic.
// [ ] Explain how you’d improve on this application design. (todo move notes to readme)

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	hs := snifty.NewHttpSniffer("en0", 1600, pcap.BlockForever, greedy)
	fmt.Printf("Snifty Sniff, the HTTP sniffer that is nifty.\nGreedy? %v\n", hs.Greedy)

	defer hs.Close()
	go hs.Listen()

	results := &snifty.Results{Counter: 0, Threshold: 12}
	done := make(chan bool)
	results.Run(done)

	complete := false
	for !complete {
		select {
		case packet := <-hs.Out:
			results.AddResult(packet)
		case <-stop:
			fmt.Println("\nExiting")
			complete = true
		}
	}
}
