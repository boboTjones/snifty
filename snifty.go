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
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type HttpSniff struct {
	IFace   string
	SnapLen int32
	Timeout time.Duration
	Max     int
	Greedy  bool
	Exit    chan bool
}

func NewHttpSniff(iface string, snaplen int32, max int, timeout time.Duration, greedy bool) *HttpSniff {
	exit := make(chan bool)
	return &HttpSniff{
		IFace:   iface,
		SnapLen: snaplen,
		Max:     max,
		Timeout: timeout,
		Greedy:  greedy,
		Exit:    exit,
	}
}

// XX ToDo(erin) implement some kind of channel so can send exit command.

func (hs *HttpSniff) Listen() {
	if hs.Greedy {
		hs.slowSniff()
	} else {
		hs.fastSniff()
	}
}

func (hs *HttpSniff) Close() {
	os.Exit(0)
}

// Slow sniff listens to tcp and filters packets
// Slows everything down.
func (hs *HttpSniff) slowSniff() {
	i := 0
	if handle, err := pcap.OpenLive(hs.IFace, hs.SnapLen, true, hs.Timeout); err != nil {
		log.Fatal(err)
		// XX ToDo(erin): baking in the ports here, for now; revisit later.
	} else if err := handle.SetBPFFilter("tcp"); err != nil {
		log.Fatal(err)
	} else {
		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		for p := range ps.Packets() {
			slowProcess(p)
			if i >= hs.Max {
				fmt.Printf("Exiting after %d packets", i)
				hs.Close()
			}
		}
	}
}

// Fast sniff only captures requests with a destination port of 80.
// Obviously runs a lot faster
func (hs *HttpSniff) fastSniff() {
	i := 0
	if handle, err := pcap.OpenLive(hs.IFace, hs.SnapLen, true, hs.Timeout); err != nil {
		log.Fatal(err)
	} else if err := handle.SetBPFFilter("tcp and dst port 80"); err != nil {
		log.Fatal(err)
	} else {
		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		for p := range ps.Packets() {
			fastProcess(p)
			if i >= hs.Max {
				fmt.Printf("Exiting after %d packets", i)
				hs.Close()
			}
		}
	}
}

func slowProcess(p gopacket.Packet) {
	heads := regexp.MustCompile(`^(GET|POST|PUT|DELETE|OPTIONS|HEAD)`)
	if a := p.ApplicationLayer(); a != nil {
		if heads.Match(a.Payload()) {
			var dest layers.TCPPort
			if tcp := p.Layer(layers.LayerTypeTCP); tcp != nil {
				if data, ok := tcp.(*layers.TCP); ok {
					dest = data.DstPort
				} else {
					log.Fatal(ok)
				}
			}
			fmt.Printf("Request to %s\n%v\n", dest, string(a.Payload()))
		}
	}
}

func fastProcess(p gopacket.Packet) {
	if a := p.ApplicationLayer(); a != nil {
		fmt.Printf("Request to port 80\n%s\n", a.Payload())
	}
}
