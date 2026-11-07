package track

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/webishdev/fail2ban-dashboard/internal/models"
	"github.com/webishdev/fail2ban-dashboard/internal/store"
)

var fixedNow = time.Date(2026, time.November, 7, 12, 0, 0, 0, time.Local)

func newTestTracker(t *testing.T) *Tracker {
	t.Helper()
	tracker, err := Open(filepath.Join(t.TempDir(), "nested", "track.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	tracker.now = func() time.Time { return fixedNow }
	t.Cleanup(func() {
		if err := tracker.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})
	return tracker
}

func jail(name string, bannedAt ...time.Time) models.Jail {
	entries := make([]models.BanEntry, len(bannedAt))
	for i, at := range bannedAt {
		entries[i] = models.BanEntry{Address: "192.0.2." + string(rune('1'+i)), BannedAt: at, JailName: name}
	}
	return models.Jail{Name: name, BannedEntries: entries}
}

func countRows(t *testing.T, tracker *Tracker) int {
	t.Helper()
	var count int
	if err := tracker.db.QueryRow("SELECT COUNT(*) FROM bans").Scan(&count); err != nil {
		t.Fatalf("count failed: %v", err)
	}
	return count
}

func sum(buckets []Bucket) int {
	total := 0
	for _, bucket := range buckets {
		total += bucket.Count
	}
	return total
}

func TestRecord_IgnoresKnownBans(t *testing.T) {
	tracker := newTestTracker(t)
	jails := []models.Jail{jail("sshd", fixedNow.Add(-time.Hour), fixedNow.Add(-2*time.Hour))}

	for range 3 {
		if err := tracker.Record(jails); err != nil {
			t.Fatalf("Record failed: %v", err)
		}
	}

	if got := countRows(t, tracker); got != 2 {
		t.Errorf("expected 2 bans, got %d", got)
	}
}

func TestRecord_SkipsZeroAndOutdatedBans(t *testing.T) {
	tracker := newTestTracker(t)
	jails := []models.Jail{jail("sshd", time.Time{}, fixedNow.AddDate(-1, 0, -1), fixedNow)}

	if err := tracker.Record(jails); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	if got := countRows(t, tracker); got != 1 {
		t.Errorf("expected 1 ban, got %d", got)
	}
}

func TestPrune_RemovesBansOlderThanOneYear(t *testing.T) {
	tracker := newTestTracker(t)
	old := fixedNow.AddDate(-1, 0, -1).Unix()
	recent := fixedNow.AddDate(0, -11, 0).Unix()
	for _, bannedAt := range []int64{old, recent} {
		if _, err := tracker.db.Exec("INSERT INTO bans (jail, address, banned_at) VALUES ('sshd', '192.0.2.1', ?)", bannedAt); err != nil {
			t.Fatalf("insert failed: %v", err)
		}
	}

	removed, err := tracker.Prune()
	if err != nil {
		t.Fatalf("Prune failed: %v", err)
	}
	if removed != 1 {
		t.Errorf("expected 1 removed ban, got %d", removed)
	}
	if got := countRows(t, tracker); got != 1 {
		t.Errorf("expected 1 remaining ban, got %d", got)
	}
}

func TestOpen_KeepsDataOnReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "track.db")
	tracker, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := tracker.Record([]models.Jail{jail("sshd", time.Now())}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if err := tracker.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	defer func() {
		_ = reopened.Close()
	}()
	if got := countRows(t, reopened); got != 1 {
		t.Errorf("expected 1 ban after reopen, got %d", got)
	}
}

func TestCounts(t *testing.T) {
	tracker := newTestTracker(t)
	jails := []models.Jail{
		jail("sshd", fixedNow, fixedNow.Add(-time.Hour), fixedNow.AddDate(0, 0, -6), fixedNow.AddDate(0, 0, -20), fixedNow.AddDate(0, -5, 0)),
		jail("nginx", fixedNow, fixedNow.AddDate(0, 0, -7)),
	}
	if err := tracker.Record(jails); err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	tests := []struct {
		name        string
		jailName    string
		r           Range
		buckets     int
		total       int
		last        int
		firstLabel  string
		lastLabel   string
		firstBucket int
	}{
		{"week all jails", "", RangeWeek, 7, 4, 3, "01.11", "07.11", 1},
		{"week sshd", "sshd", RangeWeek, 7, 3, 2, "01.11", "07.11", 1},
		{"month all jails", "", RangeMonth, 30, 6, 3, "09.10", "07.11", 0},
		{"year all jails", "", RangeYear, 12, 7, 4, "Dec 25", "Nov 26", 0},
		{"year nginx", "nginx", RangeYear, 12, 2, 1, "Dec 25", "Nov 26", 0},
		{"unknown jail", "unknown", RangeYear, 12, 0, 0, "Dec 25", "Nov 26", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buckets, err := tracker.Counts(tt.jailName, tt.r)
			if err != nil {
				t.Fatalf("Counts failed: %v", err)
			}
			if len(buckets) != tt.buckets {
				t.Fatalf("expected %d buckets, got %d", tt.buckets, len(buckets))
			}
			if got := sum(buckets); got != tt.total {
				t.Errorf("expected total %d, got %d", tt.total, got)
			}
			if got := buckets[len(buckets)-1].Count; got != tt.last {
				t.Errorf("expected %d bans in last bucket, got %d", tt.last, got)
			}
			if got := buckets[0].Count; got != tt.firstBucket {
				t.Errorf("expected %d bans in first bucket, got %d", tt.firstBucket, got)
			}
			if buckets[0].Label != tt.firstLabel || buckets[len(buckets)-1].Label != tt.lastLabel {
				t.Errorf("unexpected labels %s - %s", buckets[0].Label, buckets[len(buckets)-1].Label)
			}
		})
	}
}

func TestCounts_UnknownRange(t *testing.T) {
	tracker := newTestTracker(t)
	if _, err := tracker.Counts("", Range("decade")); err == nil {
		t.Error("expected error for unknown range")
	}
}

type mockDataSource struct {
	mutex    sync.Mutex
	handlers []store.UpdateHandler
	jails    []models.Jail
}

func (m *mockDataSource) RegisterUpdateHandler(handler store.UpdateHandler) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.handlers = append(m.handlers, handler)
}

func (m *mockDataSource) GetJails() []models.Jail {
	return m.jails
}

func TestRegister_RecordsOnUpdate(t *testing.T) {
	tracker := newTestTracker(t)
	source := &mockDataSource{jails: []models.Jail{jail("sshd", fixedNow)}}

	tracker.Register(source)
	if len(source.handlers) != 1 {
		t.Fatalf("expected 1 handler, got %d", len(source.handlers))
	}
	source.handlers[0]()

	if got := countRows(t, tracker); got != 1 {
		t.Errorf("expected 1 ban, got %d", got)
	}
}
