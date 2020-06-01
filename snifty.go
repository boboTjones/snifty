// take a config file.

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
package snifty

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	_ "github.com/tsg/gopacket/layers"
)

type HttpSniff struct {
	IFace   string
	SnapLen int32
	Timeout time.Duration
	Max     int
}

func NewHttpSniff(iface string, snaplen int32, max int, timeout time.Duration) *HttpSniff {
	return &HttpSniff{
		IFace:   iface,
		SnapLen: snaplen,
		Max:     max,
		Timeout: timeout,
	}
}

func (hs *HttpSniff) Listen() string {
	if handle, err := pcap.OpenLive(hs.IFace, hs.SnapLen, true, hs.Timeout); err != nil {
		log.Fatal(err)
		// XX ToDo(erin): baking in the ports here, for now; revisit later.
	} else if err := handle.SetBPFFilter("tcp"); err != nil {
		log.Fatal(err)
	} else {
		heads := regexp.MustCompile(`GET|POST|PUT|DELETE|OPTIONS`)
		i := 0
		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		//ps.DecodeOptions.Lazy = true
		for p := range ps.Packets() {
			i++
			if a := p.ApplicationLayer(); a != nil {
				if heads.MatchString(string(a.Payload())) {
					fmt.Printf("%v\n", string(a.Payload()))
				}
			}
			if i >= hs.Max {
				os.Exit(0)
			}
		}
	}
	return "dammit"
}

func (hs *HttpSniff) Close() {

}
