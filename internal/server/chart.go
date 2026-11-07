package server

import (
	"github.com/gofiber/fiber/v3/log"
	"github.com/webishdev/fail2ban-dashboard/internal/track"
)

// chart geometry in SVG viewBox units, the SVG is stretched to the available width
const (
	chartWidth  = 600.0
	chartHeight = 140.0
	chartBarGap = 0.2
)

var chartTitles = map[track.Range]string{
	track.RangeWeek:  "Week",
	track.RangeMonth: "Month",
	track.RangeYear:  "Year",
}

type chartData struct {
	ID     string
	Width  float64
	Height float64
	Ranges []chartRange
}

type chartRange struct {
	Key     string
	Title   string
	Checked bool
	Total   int
	Max     int
	Bars    []chartBar
}

type chartBar struct {
	X         float64
	Y         float64
	W         float64
	H         float64
	Label     string
	Count     int
	ShowLabel bool
	// MinorLabel labels are hidden on small screens
	MinorLabel bool
}

// buildChart creates the bans chart for all jails or the given jail, nil when tracking is disabled or failed.
func buildChart(tracker *track.Tracker, jailName string) *chartData {
	if tracker == nil {
		return nil
	}

	chart := &chartData{
		ID:     "bans",
		Width:  chartWidth,
		Height: chartHeight,
		Ranges: make([]chartRange, 0, len(track.Ranges)),
	}

	for index, r := range track.Ranges {
		buckets, err := tracker.Counts(jailName, r)
		if err != nil {
			log.Errorf("Could not count bans for %s: %s", r, err)
			return nil
		}
		chartRange := buildChartRange(buckets)
		chartRange.Key = string(r)
		chartRange.Title = chartTitles[r]
		chartRange.Checked = index == 0
		chart.Ranges = append(chart.Ranges, chartRange)
	}

	return chart
}

func buildChartRange(buckets []track.Bucket) chartRange {
	result := chartRange{
		Bars: make([]chartBar, len(buckets)),
	}
	if len(buckets) == 0 {
		return result
	}

	for _, bucket := range buckets {
		result.Total += bucket.Count
		result.Max = max(result.Max, bucket.Count)
	}

	// show every label for few bars, otherwise every fifth counted from the newest
	labelStep := 1
	if len(buckets) > 12 {
		labelStep = 5
	}
	// more than a week of labels does not fit on small screens, every second one is hidden there
	minorLabels := labelStep == 1 && len(buckets) > 7

	slot := chartWidth / float64(len(buckets))
	width := slot * (1 - chartBarGap)
	for index, bucket := range buckets {
		height := 0.0
		if result.Max > 0 {
			height = chartHeight * float64(bucket.Count) / float64(result.Max)
		}
		fromNewest := len(buckets) - 1 - index
		result.Bars[index] = chartBar{
			X:          slot*float64(index) + (slot-width)/2,
			Y:          chartHeight - height,
			W:          width,
			H:          height,
			Label:      bucket.Label,
			Count:      bucket.Count,
			ShowLabel:  fromNewest%labelStep == 0,
			MinorLabel: minorLabels && fromNewest%2 == 1,
		}
	}

	return result
}
