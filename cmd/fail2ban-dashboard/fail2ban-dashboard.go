package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/webishdev/fail2ban-dashboard/bootstrap"
	"github.com/webishdev/fail2ban-dashboard/geoip"
	"github.com/webishdev/fail2ban-dashboard/metrics"
	"github.com/webishdev/fail2ban-dashboard/server"
	"github.com/webishdev/fail2ban-dashboard/store"
)

var Version = "development"
var GitHash = "none"

var rootCmd = &cobra.Command{
	Use:   "fail2ban-dashboard",
	Short: "A dashboard for monitoring fail2ban",
	Long:  fmt.Sprintf("fail2ban-dashboard %s (%s) provides a web-based dashboard for monitoring fail2ban bans and jails", Version, GitHash),
	Run:   run,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number and git hash",
	Long:  "Print the version number and git hash",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("fail2ban-dashboard %s (%s)\n", Version, GitHash)
	},
}

func setupRootCommand() {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("F2BD")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	flags := rootCmd.Flags()

	flags.StringP("address", "a", "127.0.0.1:3000", "address to serve the dashboard on, also F2BD_ADDRESS")
	addressErr := viper.BindPFlag("address", flags.Lookup("address"))
	if addressErr != nil {
		fmt.Printf("Could not bind address flag: %s\n", addressErr)
		os.Exit(1)
	}

	flags.StringP("cache-dir", "c", "", "directory to cache GeoIP data, also F2BD_CACHE_DIR (default current working directory)")
	cacheDirErr := viper.BindPFlag("cache-dir", flags.Lookup("cache-dir"))
	if cacheDirErr != nil {
		fmt.Printf("Could not bind cache-dir flag: %s\n", cacheDirErr)
		os.Exit(1)
	}

	flags.String("auth-user", "", "username for basic auth, also F2BD_AUTH_USER")
	authUserErr := viper.BindPFlag("auth-user", flags.Lookup("auth-user"))
	if authUserErr != nil {
		fmt.Printf("Could not bind auth-user flag: %s\n", authUserErr)
		os.Exit(1)
	}

	flags.String("auth-password", "", "password for basic auth, also F2BD_AUTH_PASSWORD")
	authPasswordErr := viper.BindPFlag("auth-password", flags.Lookup("auth-password"))
	if authPasswordErr != nil {
		fmt.Printf("Could not bind auth-password flag: %s\n", authPasswordErr)
		os.Exit(1)
	}

	flags.StringP("socket", "s", "/var/run/fail2ban/fail2ban.sock", "location of the fail2ban socket, also F2BD_SOCKET")
	socketError := viper.BindPFlag("socket", flags.Lookup("socket"))
	if socketError != nil {
		fmt.Printf("Could not bind socket flag: %s\n", socketError)
		os.Exit(1)
	}

	flags.String("log-level", "info", "log level (trace, debug, info, warn, error), also F2BD_LOG_LEVEL")
	logLevelErr := viper.BindPFlag("log-level", flags.Lookup("log-level"))
	if logLevelErr != nil {
		fmt.Printf("Could not bind log-level flag: %s\n", logLevelErr)
		os.Exit(1)
	}

	flags.Bool("skip-version-check", false, "skip fail2ban version check (use at your own risk), also F2BD_SKIP_VERSION_CHECK")
	skipVersionCheckErr := viper.BindPFlag("skip-version-check", flags.Lookup("skip-version-check"))
	if skipVersionCheckErr != nil {
		fmt.Printf("Could not bind skip-version-check flag: %s\n", logLevelErr)
		os.Exit(1)
	}

	flags.Bool("trust-proxy-headers", false, "trust proxy headers like X-Forwarded-For, also F2BD_TRUST_PROXY_HEADERS")
	trustProxyHeadersErr := viper.BindPFlag("trust-proxy-headers", flags.Lookup("trust-proxy-headers"))
	if trustProxyHeadersErr != nil {
		fmt.Printf("Could not bind trust-proxy-headers flag: %s\n", logLevelErr)
		os.Exit(1)
	}

	flags.Int("refresh-seconds", 30, "fail2ban data refresh in seconds (value from 10 to 600), also F2BD_REFRESH_SECONDS")
	refreshSecondsErr := viper.BindPFlag("refresh-seconds", flags.Lookup("refresh-seconds"))
	if refreshSecondsErr != nil {
		fmt.Printf("Could not bind refresh-seconds flag: %s\n", logLevelErr)
		os.Exit(1)
	}

	flags.String("base-path", "/", "base path of the application, also F2BD_BASE_PATH")
	basePathError := viper.BindPFlag("base-path", flags.Lookup("base-path"))
	if basePathError != nil {
		fmt.Printf("Could not bind base-path flag: %s\n", logLevelErr)
		os.Exit(1)
	}

	flags.Bool("scheduled-geoip-download", true, "will keep GeoIP cache update even without accessing the dashboard, also F2BD_SCHEDULED_GEOIP_DOWNLOAD")
	scheduledGeoIPDownloadErr := viper.BindPFlag("scheduled-geoip-download", flags.Lookup("scheduled-geoip-download"))
	if scheduledGeoIPDownloadErr != nil {
		fmt.Printf("Could not bind scheduled-geoip-download flag: %s\n", logLevelErr)
		os.Exit(1)
	}

	flags.BoolP("metrics", "m", false, "will provide metrics endpoint, also F2BD_METRICS")
	metricsErr := viper.BindPFlag("metrics", flags.Lookup("metrics"))
	if metricsErr != nil {
		fmt.Printf("Could not bind metrics flag: %s\n", logLevelErr)
		os.Exit(1)
	}

	flags.String("metrics-address", "127.0.0.1:9100", "address to make metrics available, also F2BD_METRICS_ADDRESS")
	metricsAddressErr := viper.BindPFlag("metrics-address", flags.Lookup("metrics-address"))
	if metricsAddressErr != nil {
		fmt.Printf("Could not bind metrics-address flag: %s\n", logLevelErr)
		os.Exit(1)
	}

	rootCmd.AddCommand(versionCmd)
}

func main() {
	setupRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
}

func run(_ *cobra.Command, _ []string) {
	fmt.Printf("This is fail2ban-dashboard %s (%s)\n", Version, GitHash)

	// Load configuration from viper
	socketPath := viper.GetString("socket")
	address := viper.GetString("address")
	user := viper.GetString("auth-user")
	password := viper.GetString("auth-password")
	cacheDir := viper.GetString("cache-dir")
	logLevel := viper.GetString("log-level")
	skipVersionCheck := viper.GetBool("skip-version-check")
	trustProxyHeaders := viper.GetBool("trust-proxy-headers")
	refreshSeconds := viper.GetInt("refresh-seconds")
	basePath := viper.GetString("base-path")
	enableSchedule := viper.GetBool("scheduled-geoip-download")
	metricsEnabled := viper.GetBool("metrics")
	metricsAddress := viper.GetString("metrics-address")

	// Configure logging
	bootstrap.ConfigureLogging(logLevel)

	// Validate and fix a refresh interval
	refreshSeconds = bootstrap.ValidateRefreshSeconds(refreshSeconds)

	// Log configuration
	if trustProxyHeaders {
		log.Info("Trusting proxy headers")
	}
	log.Infof("Base path set to %s", basePath)
	log.Infof("Data refresh from fail2ban set to %d seconds", refreshSeconds)

	// Connect to fail2ban and verify version
	f2bc, fail2banVersion := bootstrap.ConnectToFail2ban(socketPath, skipVersionCheck)

	// Initialize data store
	dataStore := store.NewDataStore(f2bc, refreshSeconds)

	// Set up cache directory
	absoluteCacheDir := bootstrap.SetupCacheDirectory(cacheDir)

	// Initialize GeoIP
	geoIP := geoip.NewGeoIP(absoluteCacheDir, enableSchedule)

	// Create dashboard application
	dashboardApp := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	configuration := &server.Configuration{
		Address:           address,
		AuthUser:          user,
		AuthPassword:      password,
		BasePath:          basePath,
		TrustProxyHeaders: trustProxyHeaders,
		Fail2BanVersion:   fail2banVersion,
		Version:           Version,
	}

	if metricsEnabled {
		metricConfiguration := &metrics.Configuration{
			Address:         metricsAddress,
			Fail2BanVersion: fail2banVersion,
			Version:         Version,
		}
		if address != metricsAddress {
			metricsApp := fiber.New(fiber.Config{
				DisableStartupMessage: true,
			})

			metrics.RegisterMetricsEndpoints(metricsApp, dataStore, metricConfiguration)

			go bootstrap.StartMetricsServer(metricsApp, metricConfiguration)
		} else {
			log.Warn("Metrics address is identical to dashboard address, your metrics will be exposed the same way as the dashboard")
			metrics.RegisterMetricsEndpoints(dashboardApp, dataStore, metricConfiguration)
		}

	} else {
		log.Info("Metrics disabled")
	}

	// Register dashboard endpoints
	dashboardRegError := server.RegisterDashboardEndpoints(dashboardApp, dataStore, geoIP, configuration)
	if dashboardRegError != nil {
		log.Errorf("Register dashboard endpoints: %s\n", dashboardRegError)
		os.Exit(1)
	}

	// Start dashboard server
	go bootstrap.StartDashboardServer(dashboardApp, configuration)

	// Wait for a shutdown signal
	bootstrap.BlockUntilSignalReceived()
}
