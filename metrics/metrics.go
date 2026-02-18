package metrics

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/webishdev/fail2ban-dashboard/store"
)

type Configuration struct {
	Address         string
	Fail2BanVersion string
	Version         string
}

type metrics struct {
	reg                      *prometheus.Registry
	versionInfoMetrics       *prometheus.GaugeVec
	jailCountMetrics         prometheus.Gauge
	bannedSumMetrics         prometheus.Gauge
	jailBannedCurrentMetrics *prometheus.GaugeVec
	jailFailedCurrentMetrics *prometheus.GaugeVec
	jailBannedTotalMetrics   *prometheus.GaugeVec
	jailFailedTotalMetrics   *prometheus.GaugeVec
}

func RegisterMetricsEndpoints(app *fiber.App, dataStore *store.DataStore, configuration *Configuration) {

	currentMetrics := setupRegistry()
	currentMetrics.versionInfoMetrics.WithLabelValues(configuration.Version, configuration.Fail2BanVersion).Set(1)

	updateMetrics(currentMetrics, dataStore)

	app.Get("/metrics", adaptor.HTTPHandler(promhttp.HandlerFor(currentMetrics.reg, promhttp.HandlerOpts{})))
}

func setupRegistry() *metrics {
	result := &metrics{
		reg: prometheus.NewRegistry(),
		versionInfoMetrics: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "fail2ban_dashboard_info",
				Help: "The fail2ban Dashboard build information",
			},
			[]string{"version", "fail2ban_version"},
		),
		jailCountMetrics: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "f2b_jail_count",
				Help: "The number of jails in fail2ban",
			},
		),
		bannedSumMetrics: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "f2b_banned_total",
				Help: "The total number of banned addressees",
			},
		),
		jailBannedCurrentMetrics: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "f2b_jail_banned_current",
				Help: "Amount of banned IPs currently in jail",
			},
			[]string{"jail"},
		),
		jailFailedCurrentMetrics: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "f2b_jail_failed_current",
				Help: "Amount of failed IPs currently in jail",
			},
			[]string{"jail"},
		),
		jailBannedTotalMetrics: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "f2b_jail_banned_total",
				Help: "Amount of banned IPs total in jail",
			},
			[]string{"jail"},
		),
		jailFailedTotalMetrics: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "f2b_jail_failed_total",
				Help: "Amount of failed IPs total in jail",
			},
			[]string{"jail"},
		),
	}

	result.reg.MustRegister(result.versionInfoMetrics, result.jailCountMetrics, result.bannedSumMetrics, result.jailBannedCurrentMetrics, result.jailFailedCurrentMetrics, result.jailBannedTotalMetrics, result.jailFailedTotalMetrics)

	return result
}

// dataStoreInterface defines the minimal interface needed for updateMetrics
type dataStoreInterface interface {
	RegisterUpdateHandler(handler store.UpdateHandler)
	GetJails() []store.Jail
}

func updateMetrics(currentMetrics *metrics, dataStore dataStoreInterface) {
	dataStore.RegisterUpdateHandler(func() {
		log.Debug("Updating metrics")
		jails := dataStore.GetJails()
		jailCount := float64(len(jails))
		currentMetrics.jailCountMetrics.Set(jailCount)
		sum := 0
		for _, jail := range jails {
			numberOfBanned := float64(jail.CurrentlyBanned)
			sum += jail.CurrentlyBanned
			totalBanned := float64(jail.TotalBanned)
			numberOfFailed := float64(jail.CurrentlyFailed)
			totalFailed := float64(jail.TotalFailed)
			currentMetrics.jailBannedCurrentMetrics.WithLabelValues(jail.Name).Set(numberOfBanned)
			currentMetrics.jailBannedTotalMetrics.WithLabelValues(jail.Name).Set(totalBanned)
			currentMetrics.jailFailedCurrentMetrics.WithLabelValues(jail.Name).Set(numberOfFailed)
			currentMetrics.jailFailedTotalMetrics.WithLabelValues(jail.Name).Set(totalFailed)
		}
		currentMetrics.bannedSumMetrics.Set(float64(sum))
	})
}
