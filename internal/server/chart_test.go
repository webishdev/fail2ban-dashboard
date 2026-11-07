package server

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/webishdev/fail2ban-dashboard/internal/config"
	"github.com/webishdev/fail2ban-dashboard/internal/models"
	"github.com/webishdev/fail2ban-dashboard/internal/store"
	"github.com/webishdev/fail2ban-dashboard/internal/track"
)

func TestBuildChart_WithoutTracker(t *testing.T) {
	if chart := buildChart(nil, ""); chart != nil {
		t.Errorf("expected no chart without tracker, got %+v", chart)
	}
}

func TestBuildChartRange_Geometry(t *testing.T) {
	buckets := []track.Bucket{
		{Label: "a", Count: 0},
		{Label: "b", Count: 2},
		{Label: "c", Count: 4},
	}

	result := buildChartRange(buckets)

	if result.Total != 6 || result.Max != 4 {
		t.Errorf("expected total 6 and max 4, got %d and %d", result.Total, result.Max)
	}
	if len(result.Bars) != 3 {
		t.Fatalf("expected 3 bars, got %d", len(result.Bars))
	}
	if result.Bars[0].H != 0 || result.Bars[0].Y != chartHeight {
		t.Errorf("expected empty bar at baseline, got %+v", result.Bars[0])
	}
	if result.Bars[1].H != chartHeight/2 {
		t.Errorf("expected half height bar, got %+v", result.Bars[1])
	}
	if result.Bars[2].H != chartHeight || result.Bars[2].Y != 0 {
		t.Errorf("expected full height bar, got %+v", result.Bars[2])
	}
	for _, bar := range result.Bars {
		if !bar.ShowLabel {
			t.Errorf("expected all labels for few bars, missing %s", bar.Label)
		}
		if bar.X < 0 || bar.X+bar.W > chartWidth {
			t.Errorf("bar %s outside of chart: %+v", bar.Label, bar)
		}
	}
}

func TestBuildChartRange_LabelStep(t *testing.T) {
	result := buildChartRange(make([]track.Bucket, 30))

	shown := 0
	for _, bar := range result.Bars {
		if bar.ShowLabel {
			shown++
		}
	}
	if shown != 6 {
		t.Errorf("expected 6 labels for 30 bars, got %d", shown)
	}
	if !result.Bars[29].ShowLabel {
		t.Error("expected label for newest bar")
	}
}

func TestBuildChartRange_Empty(t *testing.T) {
	result := buildChartRange(make([]track.Bucket, 7))
	for _, bar := range result.Bars {
		if bar.H != 0 {
			t.Errorf("expected empty bars, got %+v", bar)
		}
	}
}

func createTrackTestApp(t *testing.T, tracker *track.Tracker) *fiber.App {
	t.Helper()
	dataStore := store.NewDataStore(&mockClient{jailNames: []string{"sshd"}}, 600)
	if err := dataStore.Refresh(); err != nil {
		t.Fatalf("Failed to refresh data store: %v", err)
	}
	app := fiber.New()
	if err := RegisterDashboardEndpoints(app, dataStore, nil, &config.Configuration{BasePath: "/"}, tracker); err != nil {
		t.Fatalf("Failed to register endpoints: %v", err)
	}
	return app
}

func TestChartRendering(t *testing.T) {
	tracker, err := track.Open(filepath.Join(t.TempDir(), "track.db"))
	if err != nil {
		t.Fatalf("Failed to open tracker: %v", err)
	}
	defer func() {
		_ = tracker.Close()
	}()
	jails := []models.Jail{{Name: "sshd", BannedEntries: []models.BanEntry{{Address: "192.0.2.1", BannedAt: time.Now()}}}}
	if err := tracker.Record(jails); err != nil {
		t.Fatalf("Failed to record bans: %v", err)
	}

	tests := []struct {
		name      string
		tracker   *track.Tracker
		target    string
		withChart bool
	}{
		{"overview with tracking", tracker, "/", true},
		{"detail with tracking", tracker, "/jail/sshd", true},
		{"overview without tracking", nil, "/", false},
		{"detail without tracking", nil, "/jail/sshd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := getPage(t, createTrackTestApp(t, tt.tracker), tt.target)
			hasChart := strings.Contains(body, `class="chart`)
			if hasChart != tt.withChart {
				t.Fatalf("expected chart %v, got %v", tt.withChart, hasChart)
			}
			if !tt.withChart {
				return
			}
			if !strings.Contains(body, `<details id="bans-chart"`) || !strings.Contains(body, "<summary") {
				t.Error("expected collapsible chart")
			}
			for _, r := range track.Ranges {
				if !strings.Contains(body, `data-range="`+string(r)+`"`) {
					t.Errorf("expected range %s in chart", r)
				}
			}
			if !strings.Contains(body, ": 1</title>") {
				t.Error("expected a bar with one ban")
			}
		})
	}
}
