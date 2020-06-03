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
// 6. Whenever the total traffic drops again below that value on average for the past 2
//    minutes, add another message detailing when the alert recovered.
// 7. Make sure all messages showing when alerting thresholds are crossed remain visible
//    on the page for historical reasons.
// 8. Write a test for the alerting logic.
// 9. Explain how you’d improve on this application design.

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/bobotjones/snifty"
	"github.com/google/gopacket/pcap"
)

var greedy bool
var max int

type Result struct {
	Host  string
	Paths [][]string
	Count int
}

type Results struct {
	Results []Result
}

func (r *Results) addResult(in snifty.HttpPacket) {
	for i, v := range r.Results {
		if v.Host == in.Url.Host {
			//fmt.Printf("Updating results entry for host %s\n", v.Host)
			r.Results[i].Paths = append(r.Results[i].Paths, []string{in.Url.Path})
			r.Results[i].Count++
			return
		}
	}
	//fmt.Printf("Adding new host entry %s\n", in.Url.Host)
	paths := [][]string{[]string{in.Url.Path}}
	result := Result{
		Host:  in.Url.Host,
		Paths: paths,
		Count: 1,
	}
	r.Results = append(r.Results, result)
}

func dump(r *Results) {
	fmt.Println("Collecting...")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			if len(r.Results) > 0 {
				counts := []int{}
				for _, d := range r.Results {
					counts = append(counts, d.Count)
				}
				// Really?
				sort.Sort(sort.Reverse(sort.IntSlice(counts)))
				fmt.Println("Timestamp\t\tHits\tHost")
				for x := range counts {
					_, err := fmt.Fprintf(os.Stdout, "%s\t%v\t%v\n", t.Format("01.02.2006 15:04:05.99"), r.Results[x].Count, r.Results[x].Host)
					if err != nil {
						fmt.Fprintf(os.Stderr, "%v\n", err)
					}
				}
			}
		}
	}
}

func init() {
	flag.BoolVar(&greedy, "g", false, "Run SniftySniff in greedy mode")
	flag.IntVar(&max, "m", 0, "Specific the number of packets to collect")
}

func main() {
	flag.Parse()
	results := &Results{}
	hs := snifty.NewHttpSniffer("en0", 1600, max, pcap.BlockForever, greedy)
	fmt.Printf("Snifty Sniff, the HTTP sniffer that is nifty to sift\nGreedy? %v\n", hs.Greedy)
	defer hs.Close()
	go hs.Listen()
	go dump(results)
	for {
		results.addResult(<-hs.Out)
	}

}
