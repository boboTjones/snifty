// This is where I would put the handlers for interacting with a more permanent
// storage, such as redis, ElastiCache or even a simple bitcask in /tmp. Storing
// data would improve on the design by allowing the program to exit and still
/// have all previously collected data available when restarted.

package snifty

import (
	"fmt"
	"os"
	"sort"
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
	Traffic   int
	Exit      chan bool
	Alerts    []string
	Threshold int
}

// the section for "http://my.site.com/pages/create' is "http://my.site.com/pages"

func (r *Results) Run(done chan bool) {
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
		type hc struct {
			section string
			count   int
		}
		var hits []hc
		for _, result := range r.Results {
			hits = append(hits, hc{result.Section, result.Count})
		}

		sort.SliceStable(hits, func(i, j int) bool {
			return hits[i].count > hits[j].count
		})

		fmt.Println("Timestamp\t\tHits\tSection")
		for i, hit := range hits {
			// XX ToDo(erin): for now only dump the first 5
			if i == 5 {
				break
			}
			t := time.Now()
			_, err := fmt.Fprintf(os.Stdout, "%s\t%d\t%s\n", t.Format("01.02.2006 15:04:05.99"), hit.count, hit.section)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
		}
		stats(r)
	} else {
		_, err := fmt.Fprintf(os.Stdout, "Collecting...\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
	}
}

// XX ToDo(erin): set requests per second here

func (r *Results) Sample() {
	if len(r.Samples) == 120 {
		tmp := r.Samples[:119]
		tmp = append([]int{r.Counter}, tmp...)
		r.Samples = tmp
	} else {
		r.Samples = append(r.Samples, r.Counter)
	}
	r.Counter = 0
}

func (r *Results) CheckAlerts() {
	out := 0
	for _, sample := range r.Samples {
		out += sample
	}
	if out > r.Threshold {
		alert := fmt.Sprintf("High traffic generated an alert - hits = %d, triggered at %s\n", out, time.Now().Format("01.02.2006 15:04:05.99"))
		r.Alerts = append(r.Alerts, alert)
		_, err := fmt.Fprintf(os.Stdout, alert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
	}
}

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

	_, err := fmt.Fprintf(os.Stdout, "Requests per second (avg/min/max)\t%.2f/%d/%d\nTotal traffic (bytes)\t\t\t%d\n", avg, min, max, r.Traffic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}
