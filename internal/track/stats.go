package track

import (
	"fmt"
	"slices"
	"time"
)

// Range is the time range bans are counted for.
type Range string

const (
	// RangeWeek counts bans per day for the last 7 days.
	RangeWeek Range = "week"
	// RangeMonth counts bans per day for the last 30 days.
	RangeMonth Range = "month"
	// RangeYear counts bans per month for the last 12 months.
	RangeYear Range = "year"
)

// Ranges contains all available ranges in display order.
var Ranges = []Range{RangeWeek, RangeMonth, RangeYear}

// Bucket contains the number of bans for a day or month.
type Bucket struct {
	Start time.Time
	Label string
	Count int
}

// Counts returns the number of bans per bucket for the given range, an empty jail name counts bans of all jails.
func (tracker *Tracker) Counts(jailName string, r Range) ([]Bucket, error) {
	buckets, err := tracker.buckets(r)
	if err != nil {
		return nil, err
	}

	query := "SELECT banned_at FROM bans WHERE banned_at >= ?"
	args := []any{buckets[0].Start.Unix()}
	if jailName != "" {
		query += " AND jail = ?"
		args = append(args, jailName)
	}

	rows, err := tracker.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rows.Close()
	}()

	location := tracker.now().Location()
	for rows.Next() {
		var bannedAt int64
		if err := rows.Scan(&bannedAt); err != nil {
			return nil, err
		}
		if index := bucketIndex(buckets, time.Unix(bannedAt, 0).In(location)); index >= 0 {
			buckets[index].Count++
		}
	}

	return buckets, rows.Err()
}

// buckets creates the empty buckets of the range, ending with the current day or month.
func (tracker *Tracker) buckets(r Range) ([]Bucket, error) {
	now := tracker.now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	switch r {
	case RangeWeek, RangeMonth:
		days := 7
		if r == RangeMonth {
			days = 30
		}
		buckets := make([]Bucket, days)
		for i := range buckets {
			start := today.AddDate(0, 0, i-days+1)
			buckets[i] = Bucket{Start: start, Label: start.Format("02.01")}
		}
		return buckets, nil
	case RangeYear:
		thisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		buckets := make([]Bucket, 12)
		for i := range buckets {
			start := thisMonth.AddDate(0, i-11, 0)
			buckets[i] = Bucket{Start: start, Label: start.Format("Jan 06")}
		}
		return buckets, nil
	default:
		return nil, fmt.Errorf("unknown range %q", r)
	}
}

// bucketIndex returns the index of the last bucket starting before or at the given time.
func bucketIndex(buckets []Bucket, t time.Time) int {
	for i, bucket := range slices.Backward(buckets) {
		if !t.Before(bucket.Start) {
			return i
		}
	}
	return -1
}
