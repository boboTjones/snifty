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

// HTTP isn't all on port 80. Grab all packets and filter for HTTP
// using another mechanism.

// Monitor machine mode and monitor server mode, as flags

// take a config file.

func Sniff(iface string, snaplen int32, timeout time.Duration) string {
	if handle, err := pcap.OpenLive(iface, snaplen, true, timeout); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil { // optional
		panic(err)
	} else {
		i := 0
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			i++
			//handlePacket(packet) // Do something with a packet here.
			fmt.Printf("%v\n", packet)
			if i >= 10 {
				os.Exit(0)
			}
		}
	}
	return "dammit"
}
