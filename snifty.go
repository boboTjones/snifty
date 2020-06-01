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
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func Hw() string {
	return "Hi, mom!"
}

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

func (hs *HttpSniff) Sniff() string {
	// make a struct to pass to this, containing all of the necessary information plus
	// the itera value below for the test case of 10 packets.
	if handle, err := pcap.OpenLive(hs.IFace, hs.SnapLen, true, hs.Timeout); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp"); err != nil { // optional
		panic(err)
	} else {
		i := 0
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			i++
			//handlePacket(packet) // Do something with a packet here.
			fmt.Printf("%v\n", packet)
			if i >= hs.Max {
				os.Exit(0)
			}
		}
	}
	return "dammit"
}
