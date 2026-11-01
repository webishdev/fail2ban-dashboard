package models

import "time"

type BanEntry struct {
	Address        string
	BannedAt       time.Time
	CurrentPenalty string
	BanEndsAt      time.Time
	JailName       string
	CountryCode    string
}

type JailEntry struct {
	Name          string
	BannedEntries []*BanEntry
}

type JailInfo struct {
	CurrentlyFailed int
	TotalFailed     int
	CurrentlyBanned int
	TotalBanned     int
}

type Jail struct {
	Name            string
	BannedCount     int
	BannedEntries   []BanEntry
	CurrentlyFailed int
	TotalFailed     int
	CurrentlyBanned int
	TotalBanned     int
}
