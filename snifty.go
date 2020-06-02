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
	"bytes"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type HttpPacket struct {
	Url       *url.URL
	DstPort   []byte
	UserAgent []byte
	Raw       []byte
}

type HttpSniffer struct {
	IFace   string
	SnapLen int32
	Timeout time.Duration
	Max     int
	Greedy  bool
	Out     chan HttpPacket
	Exit    chan bool
}

func NewHttpSniffer(iface string, snaplen int32, max int, timeout time.Duration, greedy bool) *HttpSniffer {
	exit := make(chan bool)
	out := make(chan HttpPacket)
	return &HttpSniffer{
		IFace:   iface,
		SnapLen: snaplen,
		Max:     max,
		Timeout: timeout,
		Greedy:  greedy,
		Out:     out,
		Exit:    exit,
	}
}

func (hs *HttpSniffer) Listen() {
	//if <-hs.Exit {
	//	hs.Close()
	//}

	bpfFilter := "tcp and dst port 80"
	i := 0

	if hs.Greedy {
		bpfFilter = "tcp"
	}

	if handle, err := pcap.OpenLive(hs.IFace, hs.SnapLen, true, hs.Timeout); err != nil {
		log.Fatal(err)
	} else if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatal(err)
	} else {
		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		for p := range ps.Packets() {
			if a := p.ApplicationLayer(); a != nil {
				if hs.Greedy {
					heads := regexp.MustCompile(`^(GET|POST)`)
					if heads.Match(a.Payload()) {
						hp := HttpPacket{}
						hp.Raw = make([]byte, len(a.Payload()))
						copy(hp.Raw, a.Payload())
						if tcp := p.Layer(layers.LayerTypeTCP); tcp != nil {
							if data, ok := tcp.(*layers.TCP); ok {
								hp.DstPort = []byte(data.DstPort.String())
								hp.processPayload()
								hs.Out <- hp
							} else {
								log.Fatal(ok)
							}
						}
					}
				} else {
					hp := HttpPacket{}
					hp.DstPort = []byte("80(http)")
					hp.Raw = make([]byte, len(a.Payload()))
					copy(hp.Raw, a.Payload())
					hp.processPayload()
					hs.Out <- hp
				}
			}
			// XX ToDo(erin): grabs Max total packets, doesn't display Max total packets.
			// Low priority. Only used for testing.
			i++
			if hs.Max != 0 && i >= hs.Max {
				fmt.Printf("Exiting after %d packets\n", i)
				hs.Close()
			}
		}
	}
}

func (hs *HttpSniffer) Close() {
	// XX ToDo(erin) figure out how to close the openlive
	// thing and do that here instead of bailing.
	os.Exit(0)
}

func (hp *HttpPacket) processPayload() {
	//defer handlePanic()
	var err error
	ua := regexp.MustCompile(`^User-Agent:`)
	s := bytes.Split(hp.Raw, []byte("\r\n"))
	for _, d := range s {
		if ua.Match(d) {
			// XX ToDo(erin): assumes there's only one colon in the UA string.
			// Currently not used for anything. Grabbed for "interesting summary statistics"
			// Might nix.
			hp.UserAgent = bytes.Split(d, []byte(": "))[1]
		} else {
			hp.UserAgent = []byte("Unknown User Agent")
		}
	}
	path := bytes.Split(s[0], []byte(" "))[1]
	host := bytes.Split(s[1], []byte(" "))[1]
	hp.Url, err = url.Parse(fmt.Sprintf("http://%s%s", host, path))
	if err != nil {
		log.Fatal(err)
	}
}
