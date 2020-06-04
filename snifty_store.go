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

func (r *Results) Dump() {
	fmt.Println("Collecting...")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case t := <-ticker.C:
			if len(r.Results) > 0 {
				type hc struct {
					section string
					count   int
				}

				var hits []hc
				for _, r := range r.Results {
					hits = append(hits, hc{r.Section, r.Count})
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
					_, err := fmt.Fprintf(os.Stdout, "%s\t%d\t%s\n", t.Format("01.02.2006 15:04:05.99"), hc.count, hc.section)
					if err != nil {
						fmt.Fprintf(os.Stderr, "%v\n", err)
					}
				}
				avgminmax(r.Samples)
			}
		}
	}
}

//    2 minute window for avg rate
//    average the last seven samples in the array

func (r *Results) Sample() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case _ = <-ticker.C:
			// every second sample the counter to see how much it has increased
			// collect 120 samples
			sample(r)
			//fmt.Println(r.Samples)
		}
	}
}

func sample(r *Results) {
	if len(r.Samples) == 120 {
		tmp := r.Samples[:119]
		tmp = append([]int{r.Counter}, tmp...)
		r.Samples = tmp
	} else {
		r.Samples = append(r.Samples, r.Counter)
	}
	r.Counter = 0
}

func avgminmax(x []int) {
	var avg float64
	total := 0
	//si := len(x) - 7
	for _, v := range x {
		total += v
	}
	//average all of the samples or last seven?
	avg = float64(total) / float64(len(x))
	sorted := make([]int, len(x))
	copy(sorted, sort.IntSlice(x))
	_, err := fmt.Fprintf(os.Stdout, "Requests per second (avg/min/max)\t%.2f/%d/%d\n", avg, sorted[0], sorted[len(sorted)-1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
}
