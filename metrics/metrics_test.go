package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/webishdev/fail2ban-dashboard/store"
)

func TestSetupRegistry(t *testing.T) {
	t.Run("creates registry with all metrics", func(t *testing.T) {
		m := setupRegistry()

		if m.reg == nil {
			t.Error("expected registry to be non-nil")
		}
		if m.versionInfoMetrics == nil {
			t.Error("expected versionInfoMetrics to be non-nil")
		}
		if m.jailCountMetrics == nil {
			t.Error("expected jailCountMetrics to be non-nil")
		}
		if m.jailBannedCurrentMetrics == nil {
			t.Error("expected jailBannedCurrentMetrics to be non-nil")
		}
		if m.jailFailedCurrentMetrics == nil {
			t.Error("expected jailFailedCurrentMetrics to be non-nil")
		}
		if m.jailBannedTotalMetrics == nil {
			t.Error("expected jailBannedTotalMetrics to be non-nil")
		}
		if m.jailFailedTotalMetrics == nil {
			t.Error("expected jailFailedTotalMetrics to be non-nil")
		}
	})

	t.Run("metrics have correct names and labels", func(t *testing.T) {
		m := setupRegistry()

		// Set values on all metrics so they appear in the registry
		m.versionInfoMetrics.WithLabelValues("1.0.0", "0.11.2").Set(1)
		m.jailCountMetrics.Set(1)
		m.jailBannedCurrentMetrics.WithLabelValues("test").Set(1)
		m.jailFailedCurrentMetrics.WithLabelValues("test").Set(1)
		m.jailBannedTotalMetrics.WithLabelValues("test").Set(1)
		m.jailFailedTotalMetrics.WithLabelValues("test").Set(1)

		metricFamilies, err := m.reg.Gather()
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}

		metricsMap := make(map[string]*dto.MetricFamily)
		for _, mf := range metricFamilies {
			metricsMap[*mf.Name] = mf
		}

		// Verify all metrics are registered
		if _, ok := metricsMap["fail2ban_dashboard_info"]; !ok {
			t.Error("expected metricsMap to contain 'fail2ban_dashboard_info'")
		}
		if _, ok := metricsMap["f2b_jail_count"]; !ok {
			t.Error("expected metricsMap to contain 'f2b_jail_count'")
		}
		if _, ok := metricsMap["f2b_jail_banned_current"]; !ok {
			t.Error("expected metricsMap to contain 'f2b_jail_banned_current'")
		}
		if _, ok := metricsMap["f2b_jail_failed_current"]; !ok {
			t.Error("expected metricsMap to contain 'f2b_jail_failed_current'")
		}
		if _, ok := metricsMap["f2b_jail_banned_total"]; !ok {
			t.Error("expected metricsMap to contain 'f2b_jail_banned_total'")
		}
		if _, ok := metricsMap["f2b_jail_failed_total"]; !ok {
			t.Error("expected metricsMap to contain 'f2b_jail_failed_total'")
		}

		// Verify help texts
		expectedHelp := "The fail2ban Dashboard build information"
		if actualHelp := *metricsMap["fail2ban_dashboard_info"].Help; actualHelp != expectedHelp {
			t.Errorf("expected help text %q, got %q", expectedHelp, actualHelp)
		}
		expectedHelp = "The number of jails in fail2ban"
		if actualHelp := *metricsMap["f2b_jail_count"].Help; actualHelp != expectedHelp {
			t.Errorf("expected help text %q, got %q", expectedHelp, actualHelp)
		}
		expectedHelp = "Amount of banned IPs currently in jail"
		if actualHelp := *metricsMap["f2b_jail_banned_current"].Help; actualHelp != expectedHelp {
			t.Errorf("expected help text %q, got %q", expectedHelp, actualHelp)
		}
		expectedHelp = "Amount of failed IPs currently in jail"
		if actualHelp := *metricsMap["f2b_jail_failed_current"].Help; actualHelp != expectedHelp {
			t.Errorf("expected help text %q, got %q", expectedHelp, actualHelp)
		}
		expectedHelp = "Amount of banned IPs total in jail"
		if actualHelp := *metricsMap["f2b_jail_banned_total"].Help; actualHelp != expectedHelp {
			t.Errorf("expected help text %q, got %q", expectedHelp, actualHelp)
		}
		expectedHelp = "Amount of failed IPs total in jail"
		if actualHelp := *metricsMap["f2b_jail_failed_total"].Help; actualHelp != expectedHelp {
			t.Errorf("expected help text %q, got %q", expectedHelp, actualHelp)
		}
	})

	t.Run("gauge vec metrics have correct labels", func(t *testing.T) {
		m := setupRegistry()

		// Set values with labels
		m.jailBannedCurrentMetrics.WithLabelValues("sshd").Set(5)
		m.jailFailedCurrentMetrics.WithLabelValues("nginx").Set(10)

		// Verify metrics can be collected
		metricFamilies, err := m.reg.Gather()
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if len(metricFamilies) == 0 {
			t.Error("expected metricFamilies to be non-empty")
		}
	})
}

// mockDataStore is a simple mock for DataStore that allows us to test updateMetrics
type mockDataStore struct {
	jails   []store.Jail
	handler store.UpdateHandler
}

func newMockDataStore(jails []store.Jail) *mockDataStore {
	return &mockDataStore{
		jails: jails,
	}
}

func (m *mockDataStore) GetJails() []store.Jail {
	return m.jails
}

func (m *mockDataStore) RegisterUpdateHandler(handler store.UpdateHandler) {
	m.handler = handler
}

func (m *mockDataStore) TriggerUpdate() {
	if m.handler != nil {
		m.handler()
	}
}

func TestUpdateMetrics(t *testing.T) {
	t.Run("registers update handler", func(t *testing.T) {
		m := setupRegistry()
		mock := newMockDataStore(nil)

		updateMetrics(m, mock)

		if mock.handler == nil {
			t.Error("expected handler to be non-nil")
		}
	})

	t.Run("updates metrics with jail data", func(t *testing.T) {
		m := setupRegistry()
		mock := newMockDataStore([]store.Jail{
			{
				Name:            "sshd",
				CurrentlyBanned: 5,
				TotalBanned:     100,
				CurrentlyFailed: 10,
				TotalFailed:     250,
			},
			{
				Name:            "nginx",
				CurrentlyBanned: 3,
				TotalBanned:     50,
				CurrentlyFailed: 7,
				TotalFailed:     120,
			},
		})

		updateMetrics(m, mock)
		mock.TriggerUpdate()

		// Verify jail count
		if actual := testutil.ToFloat64(m.jailCountMetrics); actual != 2.0 {
			t.Errorf("expected jail count 2.0, got %f", actual)
		}

		// Verify sshd metrics
		sshdBannedCurrent, err := m.jailBannedCurrentMetrics.GetMetricWithLabelValues("sshd")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if actual := testutil.ToFloat64(sshdBannedCurrent); actual != 5.0 {
			t.Errorf("expected sshd banned current 5.0, got %f", actual)
		}

		sshdBannedTotal, err := m.jailBannedTotalMetrics.GetMetricWithLabelValues("sshd")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if actual := testutil.ToFloat64(sshdBannedTotal); actual != 100.0 {
			t.Errorf("expected sshd banned total 100.0, got %f", actual)
		}

		sshdFailedCurrent, err := m.jailFailedCurrentMetrics.GetMetricWithLabelValues("sshd")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if actual := testutil.ToFloat64(sshdFailedCurrent); actual != 10.0 {
			t.Errorf("expected sshd failed current 10.0, got %f", actual)
		}

		sshdFailedTotal, err := m.jailFailedTotalMetrics.GetMetricWithLabelValues("sshd")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if actual := testutil.ToFloat64(sshdFailedTotal); actual != 250.0 {
			t.Errorf("expected sshd failed total 250.0, got %f", actual)
		}

		// Verify nginx metrics
		nginxBannedCurrent, err := m.jailBannedCurrentMetrics.GetMetricWithLabelValues("nginx")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if actual := testutil.ToFloat64(nginxBannedCurrent); actual != 3.0 {
			t.Errorf("expected nginx banned current 3.0, got %f", actual)
		}

		nginxBannedTotal, err := m.jailBannedTotalMetrics.GetMetricWithLabelValues("nginx")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if actual := testutil.ToFloat64(nginxBannedTotal); actual != 50.0 {
			t.Errorf("expected nginx banned total 50.0, got %f", actual)
		}

		nginxFailedCurrent, err := m.jailFailedCurrentMetrics.GetMetricWithLabelValues("nginx")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if actual := testutil.ToFloat64(nginxFailedCurrent); actual != 7.0 {
			t.Errorf("expected nginx failed current 7.0, got %f", actual)
		}

		nginxFailedTotal, err := m.jailFailedTotalMetrics.GetMetricWithLabelValues("nginx")
		if err != nil {
			t.Errorf("expected no error, got: %v", err)
		}
		if actual := testutil.ToFloat64(nginxFailedTotal); actual != 120.0 {
			t.Errorf("expected nginx failed total 120.0, got %f", actual)
		}
	})

	t.Run("handles empty jails list", func(t *testing.T) {
		m := setupRegistry()
		mock := newMockDataStore([]store.Jail{})

		updateMetrics(m, mock)
		mock.TriggerUpdate()

		// Verify jail count is 0
		if actual := testutil.ToFloat64(m.jailCountMetrics); actual != 0.0 {
			t.Errorf("expected jail count 0.0, got %f", actual)
		}
	})

	t.Run("updates metrics on subsequent calls", func(t *testing.T) {
		m := setupRegistry()
		mock := newMockDataStore([]store.Jail{
			{
				Name:            "sshd",
				CurrentlyBanned: 5,
				TotalBanned:     100,
				CurrentlyFailed: 10,
				TotalFailed:     250,
			},
		})

		updateMetrics(m, mock)
		mock.TriggerUpdate()

		// First check
		if actual := testutil.ToFloat64(m.jailCountMetrics); actual != 1.0 {
			t.Errorf("expected jail count 1.0, got %f", actual)
		}
		sshdBannedCurrent, _ := m.jailBannedCurrentMetrics.GetMetricWithLabelValues("sshd")
		if actual := testutil.ToFloat64(sshdBannedCurrent); actual != 5.0 {
			t.Errorf("expected sshd banned current 5.0, got %f", actual)
		}

		// Update mock data
		mock.jails = []store.Jail{
			{
				Name:            "sshd",
				CurrentlyBanned: 15,
				TotalBanned:     200,
				CurrentlyFailed: 20,
				TotalFailed:     350,
			},
			{
				Name:            "nginx",
				CurrentlyBanned: 2,
				TotalBanned:     25,
				CurrentlyFailed: 4,
				TotalFailed:     60,
			},
		}

		mock.TriggerUpdate()

		// Verify updated metrics
		if actual := testutil.ToFloat64(m.jailCountMetrics); actual != 2.0 {
			t.Errorf("expected jail count 2.0, got %f", actual)
		}
		sshdBannedCurrent, _ = m.jailBannedCurrentMetrics.GetMetricWithLabelValues("sshd")
		if actual := testutil.ToFloat64(sshdBannedCurrent); actual != 15.0 {
			t.Errorf("expected sshd banned current 15.0, got %f", actual)
		}

		nginxBannedCurrent, _ := m.jailBannedCurrentMetrics.GetMetricWithLabelValues("nginx")
		if actual := testutil.ToFloat64(nginxBannedCurrent); actual != 2.0 {
			t.Errorf("expected nginx banned current 2.0, got %f", actual)
		}
	})
}
