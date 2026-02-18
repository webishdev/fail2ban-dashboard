package bootstrap

import (
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/webishdev/fail2ban-dashboard/metrics"
	"github.com/webishdev/fail2ban-dashboard/server"
)

func StartDashboardServer(app *fiber.App, config *server.Configuration) {
	log.Infof("Dashboard available at address %s", config.Address)
	serveError := app.Listen(config.Address)
	if serveError != nil {
		log.Errorf("Could not start server: %s\n", serveError)
		os.Exit(1)
	}
}

func StartMetricsServer(metricsApp *fiber.App, config *metrics.Configuration) {
	log.Infof("Metrics available at address %s", config.Address)
	serveError := metricsApp.Listen(config.Address)
	if serveError != nil {
		log.Errorf("Could not start server: %s\n", serveError)
		os.Exit(1)
	}
}
