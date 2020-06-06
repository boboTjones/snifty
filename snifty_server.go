// This is where I would put an HTTP server with an API that reaches into Snifty Storage
// (bitcask, redis, elasticache). So that instead of having snifty push the data to stdout,
// there could be a separate client component (ncurses, tcell, termbox, React) that does
// the heavy lifting of polling the API and displaying the results on timers.
//
package snifty

import "time"

type dumper interface {
	Dump()
}

type sampler interface {
	Sample()
}

type alerter interface {
	CheckAlerts()
}

// DumpTicker runs every 10 seconds to run Dump() to the console.
func DumpTicker(d dumper, done chan bool) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.Dump()
		case <-done:
			return
		}
	}
}

// SampleTicker runs every second to run the Sample() function.
func SampleTicker(s sampler, done chan bool) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case _ = <-ticker.C:
			s.Sample()
		case <-done:
			return
		}
	}
}

// AlertTicker runs every two minutes and checks for alerts.
func AlertTicker(a alerter, done chan bool) {
	ticker := time.NewTicker(120 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case _ = <-ticker.C:
			a.CheckAlerts()
		case <-done:
			return
		}
	}
}
