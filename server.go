// This is where I would put an HTTP server with an API that reaches into Snifty Storage
// (bitcask, redis, elasticache). So that instead of having snifty push the data to stdout,
// there could be a separate client component (ncurses, tcell, termbox, React) that does
// the heavy lifting of polling the API and displaying the results on timers.
//
package snifty

import (
	"context"
	"time"
)

const (
	halfSecond = 500 * time.Millisecond
	oneSecond  = 1 * time.Second
	tenSeconds = 10 * time.Second
	twoMinutes = 120 * time.Second
)

// DumpTicker runs every 10 seconds to run Dump() to the console.
func DumpTicker(r *Results, ctx context.Context) {
	ticker := time.NewTicker(tenSeconds)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.Dump()
		case <-ctx.Done():
			return
		}
	}
}

// SampleTicker runs every half second to collect traffic samples with the Sample() function.
func SampleTicker(r *Results, ctx context.Context) {
	ticker := time.NewTicker(halfSecond)
	defer ticker.Stop()
	for {
		select {
		case _ = <-ticker.C:
			r.Sample()
		case <-ctx.Done():
			return
		}
	}
}

// AlertTicker runs every two minutes and checks for alerts.
func AlertTicker(r *Results, ctx context.Context) {
	ticker := time.NewTicker(twoMinutes)
	defer ticker.Stop()
	for {
		select {
		case _ = <-ticker.C:
			r.CheckAlerts()
		case <-ctx.Done():
			return
		}
	}
}
