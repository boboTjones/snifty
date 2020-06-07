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
//    2 minute window for avg rate
//    every second sample the counter to see how much it has increased
//   array of all samples collected up to 120 elements (ring buffer)
//   average the last seven samples in the array? all of the samples?
// 6. Make sure all messages showing when alerting thresholds are crossed remain visible
//    on the page for historical reasons.
// 7. Write a test for the alerting logic.
// 8. Explain how you’d improve on this application design.
package snifty

import (
	"bytes"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type HttpPacket struct {
	Section   string
	DstPort   []byte
	UserAgent []byte
	Raw       []byte
}

type HttpSniffer struct {
	IFace   string
	SnapLen int32
	Timeout time.Duration
	Greedy  bool
	Handle  *pcap.Handle
	Out     chan HttpPacket
}

type Config struct {
	Greedy    bool   `json:"greedy"`
	Max       int    `json:"max"`
	Timeout   string `json:"timeout"`
	IFace     string `json:"iface"`
	Snaplen   int32  `json:"snaplen"`
	Threshold int    `json:"threshold"`
	// some other things, like maybe specific host?
}

func NewHttpSniffer(c *Config) *HttpSniffer {
	out := make(chan HttpPacket)
	var timeout time.Duration
	var err error
	if c.Timeout == "" {
		timeout = pcap.BlockForever
	} else {
		timeout, err = time.ParseDuration(c.Timeout)
		if err != nil {
			log.Fatalf("Timeout won't parse. Here's why: %s\n", err)
		}
	}
	return &HttpSniffer{
		IFace:   c.IFace,
		SnapLen: c.Snaplen,
		Timeout: timeout,
		Greedy:  c.Greedy,
		Out:     out,
	}
}

func (hs *HttpSniffer) Listen() {
	heads := regexp.MustCompile(`^(GET|POST)`)
	bpfFilter := "tcp and dst port 80"
	var err error

	if hs.Greedy {
		bpfFilter = "tcp"
	}

	if hs.Handle, err = pcap.OpenLive(hs.IFace, hs.SnapLen, true, hs.Timeout); err != nil {
		log.Fatal(err)
	}

	if err = hs.Handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatal(err)
	}

	ps := gopacket.NewPacketSource(hs.Handle, hs.Handle.LinkType())
	for p := range ps.Packets() {
		if a := p.ApplicationLayer(); a != nil {
			if hs.Greedy {
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
	}
}

func (hs *HttpSniffer) Close() {
	hs.Handle.Close()
}

func (hp *HttpPacket) processPayload() {
	s := bytes.Split(hp.Raw, []byte("\r\n"))
	for _, d := range s {
		if bytes.HasPrefix(d, []byte("User-Agent:")) {
			// XX ToDo(erin): assumes there's only one colon in the UA string, which is Capitalized.
			// Currently not used for anything. Grabbed for "interesting summary statistics"
			// Might nix.
			hp.UserAgent = bytes.Split(d, []byte(": "))[1]
		} else {
			hp.UserAgent = []byte("Unknown User Agent")
		}
	}
	rgx := regexp.MustCompile(`\/([a-z][0-9]+)\/|\/([\w\.html-]+)`)
	section := rgx.Find(s[0])
	host := bytes.Split(s[1], []byte(" "))[1]
	hp.Section = fmt.Sprintf("%s%s", host, section)
}
