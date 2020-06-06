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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"

	"github.com/bobotjones/snifty"
)

var greedy, version bool
var max int
var file string

func init() {
	flag.BoolVar(&greedy, "g", false, "Run SniftySniff in greedy mode")
	flag.BoolVar(&version, "v", false, "Print version and exit")
	flag.StringVar(&file, "f", file, "Specify a config file")
}

func main() {
	flag.Parse()
	if version {
		fmt.Println("Snifty Sniff version 0.1. We can only go up from here.")
		os.Exit(0)
	}

	config := &snifty.Config{}

	if file != "" {
		c, err := ioutil.ReadFile(file)
		if err != nil {
			fmt.Printf("Unable to read config file %s. Please try again.\n", file)
			os.Exit(1)
		}
		if err := json.Unmarshal(c, config); err != nil {
			fmt.Printf("Unable to parse config file %s:\n(%v)\nPlease try again.\n", err, file)
			os.Exit(1)
		}
	} else {
		config.IFace = "en0"
		config.Snaplen = 1600
		config.Timeout = ""
		config.Greedy = false
	}

	hs := snifty.NewHttpSniffer(config)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("%T\n", hs)
	fmt.Printf("Snifty Sniff, the HTTP sniffer that is nifty.\nGreedy? %v\n", hs.Greedy)

	defer hs.Close()
	go hs.Listen()

	results := &snifty.Results{Counter: 0, Threshold: config.Threshold}
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
