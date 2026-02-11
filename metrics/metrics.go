package metrics

import (
	"net/http"
	"os"

	"github.com/gofiber/fiber/v2/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/webishdev/fail2ban-dashboard/store"
)

type Configuration struct {
	Address         string
	Fail2BanVersion string
	Version         string
}

func ServeMetrics(dataStore *store.DataStore, configuration *Configuration) {

	var versionInfoMetrics = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "fail2ban_dashboard_info",
			Help: "The fail2ban Dashboard build information",
		},
		[]string{"version", "fail2ban_version"},
	)

	var jailCountMetrics = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "f2b_jail_count",
			Help: "The number of jails in fail2ban",
		},
	)

	var jailBannedCurrentMetrics = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "f2b_jail_banned_current",
			Help: "Amount of banned IPs currently in jail",
		},
		[]string{"jail"},
	)

	var jailFailedCurrentMetrics = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "f2b_jail_failed_current",
			Help: "Amount of failed IPs currently in jail",
		},
		[]string{"jail"},
	)

	var jailBannedTotalMetrics = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "f2b_jail_banned_total",
			Help: "Amount of banned IPs total in jail",
		},
		[]string{"jail"},
	)

	var jailFailedTotalMetrics = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "f2b_jail_failed_total",
			Help: "Amount of failed IPs total in jail",
		},
		[]string{"jail"},
	)

	reg := prometheus.NewRegistry()
	reg.MustRegister(versionInfoMetrics, jailCountMetrics, jailBannedCurrentMetrics, jailFailedCurrentMetrics, jailBannedTotalMetrics, jailFailedTotalMetrics)
	versionInfoMetrics.WithLabelValues(configuration.Version, configuration.Fail2BanVersion).Set(1)

	log.Infof("Metrics enabled at %s", configuration.Address)
	go listen(configuration.Address, reg)

	dataStore.RegisterUpdateHandler(func() {
		log.Debug("Updating metrics")
		jails := dataStore.GetJails()
		jailCount := float64(len(jails))
		jailCountMetrics.Set(jailCount)
		for _, jail := range jails {
			numberOfBanned := float64(jail.CurrentlyBanned)
			totalBanned := float64(jail.TotalBanned)
			numberOfFailed := float64(jail.CurrentlyFailed)
			totalFailed := float64(jail.TotalFailed)
			jailBannedCurrentMetrics.WithLabelValues(jail.Name).Set(numberOfBanned)
			jailBannedTotalMetrics.WithLabelValues(jail.Name).Set(totalBanned)
			jailFailedCurrentMetrics.WithLabelValues(jail.Name).Set(numberOfFailed)
			jailFailedTotalMetrics.WithLabelValues(jail.Name).Set(totalFailed)
		}

	})
}

func listen(address string, reg *prometheus.Registry) {
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	metricsError := http.ListenAndServe(address, nil)
	if metricsError != nil {
		log.Errorf("Could not start metrics: %s\n", metricsError)
		os.Exit(1)
	}
}
