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
	Results []Result
	Samples []int
	Counter int
	Exit    chan bool
}

type Alerts struct {
	Alert []byte
}

// the section for "http://my.site.com/pages/create' is "http://my.site.com/pages"

func (r *Results) AddResult(in HttpPacket) {
	r.Counter++
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

func (r *Results) Close() {
	return
}

func (r *Results) Run() {
	done := make(chan bool, 1)
	go DumpTicker(r, done)
	go SampleTicker(r, done)
}

func (r *Results) AvgMinMax() {
	samples := make([]int, len(r.Samples))
	copy(samples, sort.IntSlice(r.Samples))
	var avg float64
	total := 0
	for _, sample := range samples {
		total += sample
	}
	avg = float64(total) / float64(len(samples))
	_, err := fmt.Fprintf(os.Stdout, "Requests per second (avg/min/max)\t%.2f/%d/%d\n", avg, samples[0], samples[len(samples)-1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
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
	} else {
		_, err := fmt.Fprintf(os.Stdout, "Collecting...")
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

func (a *Alerts) CheckAlerts() {
	fmt.Println("High traffic generated an alert - hits = {value}, triggered at {time}")
}
