package snifty

import (
	"fmt"
	"os"
	"sort"
	"time"
)

// Future bitcask storage?

// tmp db unique string
// store in database using url string as key
// if found, increment counter
// if not found, create new entry
// remove db on exit

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
		sort.Slice(hits, func(i, j int) bool {
			return hits[i].count > hits[j].count
		})
		fmt.Println("Timestamp\t\tHits\tSection")
		for i, hc := range hits {
			// XX ToDo(erin): for now only dump the first 5
			if i == 5 {
				break
			}
			t := time.Now()
			_, err := fmt.Fprintf(os.Stdout, "%s\t%d\t%s\n", t.Format("01.02.2006 15:04:05.99"), hc.count, hc.section)
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
	if out > 0 {
		alert := fmt.Sprintf("High traffic generated an alert - hits = %d, triggered at %s\n", out, time.Now().String())
		r.Alerts = append(r.Alerts, alert)
		_, err := fmt.Fprintf(os.Stdout, alert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
	}
}

func stats(r *Results) {
	samples := make([]int, len(r.Samples))
	copy(samples, sort.IntSlice(r.Samples))
	var avg float64
	total := 0
	for _, sample := range samples {
		total += sample
	}
	avg = float64(total) / float64(len(samples))
	_, err := fmt.Fprintf(os.Stdout, "Requests per second (avg/min/max)\t%.2f/%d/%d\nTotal traffic (bytes)\t\t\t%d\n", avg, samples[0], samples[len(samples)-1], r.Traffic)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}
