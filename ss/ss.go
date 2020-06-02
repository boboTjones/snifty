// Create a simple console program that monitors HTTP traffic on your machine:
// 1. Sniff network traffic to detect HTTP activity.
// 2. Every 10s, display in the console the sections of the web site with the most
//    hits (a section is defined as being what's before the second '/' in a URL. i.e.
//    the section for "http://my.site.com/pages/create' is "http://my.site.com/pages"),
//    as well as interesting summary statistics on the traffic as a whole.
// 3. Make sure a user can keep the console app running and monitor traffic on their machine.
// 4. Whenever total traffic for the past 2 minutes exceeds a certain number on average,
//    add a message saying that “High traffic generated an alert - hits = {value}, triggered at {time}”.
// 5. Whenever the total traffic drops again below that value on average for the past 2
//    minutes, add another message detailing when the alert recovered.
// 6. Whenever the total traffic drops again below that value on average for the past 2
//    minutes, add another message detailing when the alert recovered.
// 7. Make sure all messages showing when alerting thresholds are crossed remain visible
//    on the page for historical reasons.
// 8. Write a test for the alerting logic.
// 9. Explain how you’d improve on this application design.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/bobotjones/snifty"
	"github.com/google/gopacket/pcap"
	"github.com/prologic/bitcask"
)

var greedy bool
var max int

func init() {
	flag.BoolVar(&greedy, "g", false, "Run SniftySniff in greedy mode")
	flag.IntVar(&max, "m", 0, "Specific the number of packets to collect")
}

func main() {
	flag.Parse()
	db, err := bitcask.Open("/tmp/db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	fmt.Printf("%T\n", db)

	// Possibly if max is set, pcap.BlockForever breaks it.
	hs := snifty.NewHttpSniffer("en0", 1600, max, pcap.BlockForever, greedy)
	fmt.Printf("Sniffing HTTP traffic. Greedy? %v\n", hs.Greedy)
	defer hs.Close()
	go hs.Listen()

	for {
		x := <-hs.Out
		data, err := json.Marshal(x)
		if err != nil {
			log.Fatal(err)
		}
		db.Put([]byte(x.Url.String()), data)
		//fmt.Printf("%v\n", data)
		fmt.Printf("OUTPUT: %v\n", x.Url.String())
		//fmt.Printf("%s\n", <-db.Keys())
	}
}

// tmp db unique string
// store in database using url string as key
// if found, increment counter
// if not found, create new entry
// remove db on exit
