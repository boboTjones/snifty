// This is where I would put the handlers for interacting with a more permanent
// storage, such as redis, ElastiCache or even a simple bitcask in /tmp. Storing
// data would improve on the design by allowing the program to exit and still
/// have all previously collected data available when restarted.

package snifty

import (
	"bytes"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Result struct {
	Section string
	Count   int
}

type Results struct {
	Results   []Result
	Samples   []int
	Counter   int
	Total     int
	Traffic   int
	Exit      chan bool
	Alerts    *bytes.Buffer
	Threshold int
	Start     time.Time
	Clear     bool
}

var sLock sync.RWMutex

// the section for "http://my.site.com/pages/create' is "http://my.site.com/pages"

func (r *Results) Run(done chan bool) {
	r.Start = time.Now()
	r.Clear = false
	go DumpTicker(r, done)
	go SampleTicker(r, done)
	go AlertTicker(r, done)
}

func (r *Results) Close() {
	return
}

func (r *Results) AddResult(in HttpPacket) {
	//fmt.Printf("adding %v\n", in)
	r.Counter++
	r.Total++
	r.Traffic = r.Traffic + len(in.Raw)
	for i, v := range r.Results {
		if v.Section == in.Section {
			//fmt.Printf("Updating count for section %s\n", in.Section)
			r.Results[i].Count++
			return
		}
	}
	//fmt.Printf("Adding new section %s\n", in.Section)
	result := Result{
		Section: in.Section,
		Count:   1,
	}
	r.Results = append(r.Results, result)
}

func (r *Results) Dump() {
	if len(r.Results) > 0 {
		sLock.RLock()
		results := make([]Result, len(r.Results))
		copy(results, r.Results)
		sLock.RUnlock()

		sort.SliceStable(results, func(i, j int) bool {
			return results[i].Count > results[j].Count
		})

		t := time.Now()
		fmt.Println("------------------------------------------------------------------------------------")
		fmt.Printf("%s\tHits\tSection\n", t.Format("01.02.2006 15:04:05.99"))
		fmt.Println("------------------------------------------------------------------------------------")

		for i, hit := range results {
			// XX ToDo(erin): for now only dump the first 5
			if i == 5 {
				break
			}
			fmt.Printf("                      \t %d\t%s\n", hit.Count, hit.Section)
		}
		stats(r)
	} else {
		now := time.Now()
		fmt.Printf("%s\tWaiting for traffic. Time elapsed: %.2fs\n", now.Format("01.02.2006 15:04:05.99"), now.Sub(r.Start).Seconds())
	}
}

func (r *Results) Sample() {
	sLock.RLock()
	r.Samples = append(r.Samples, r.Counter)
	if len(r.Samples) == 120 {
		r.Samples = r.Samples[1:]
	}
	r.Counter = 0
	sLock.RUnlock()
}

func (r *Results) CheckAlerts() {
	out := 0

	sLock.RLock()
	samples := make([]int, len(r.Samples))
	copy(samples, r.Samples)
	sLock.RUnlock()

	for _, sample := range samples {
		out += sample
	}

	if out <= r.Threshold && r.Clear {
		alert := fmt.Sprintf("High traffic alert cleared at %s", time.Now().Format("01.02.2006 15:04:05.99"))

		sLock.RLock()
		r.Alerts.WriteString(alert)
		r.Clear = false
		sLock.RUnlock()

		fmt.Println("----------ALERT-------------------------------------------------------------------")
		fmt.Println(alert)
		fmt.Println("------------------------------------------------------------------------------------")
	}

	if out > r.Threshold && !r.Clear {
		alert := fmt.Sprintf("High traffic generated an alert - hits = %d, triggered at %s", out, time.Now().Format("01.02.2006 15:04:05.99"))

		sLock.RLock()
		r.Alerts.WriteString(alert)
		r.Clear = true
		sLock.RUnlock()

		fmt.Println("----------ALERT-------------------------------------------------------------------")
		fmt.Println(alert)
		fmt.Println("------------------------------------------------------------------------------------")
	}
}

// XX ToDo(erin): toggle with flag.

func stats(r *Results) {
	samples := make([]int, len(r.Samples))
	copy(samples, r.Samples)
	avg := float32(0)
	total := 0
	max := 0
	min := 2147483647

	for _, sample := range samples {
		total += sample
		if sample > max {
			max = sample
		}
		if sample < min {
			min = sample
		}
	}

	avg = float32(total) / float32(len(samples))
	fmt.Println("------------------------------------------------------------------------------------")
	fmt.Printf("Requests per second (avg/min/max)\t%.2f/%d/%d\n", avg, min, max)
	fmt.Printf("Total requests\t\t\t\t%d\n", r.Total)
	fmt.Printf("Total traffic (bytes)\t\t\t%d\n", r.Traffic)
}
