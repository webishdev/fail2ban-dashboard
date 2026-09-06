package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/webishdev/fail2ban-dashboard/bootstrap"
	"github.com/webishdev/fail2ban-dashboard/config"
	"github.com/webishdev/fail2ban-dashboard/geoip"
	"github.com/webishdev/fail2ban-dashboard/metrics"
	"github.com/webishdev/fail2ban-dashboard/server"
	"github.com/webishdev/fail2ban-dashboard/store"
)

var Version = "development"
var GitHash = "none"

func setupRootCommand() *cobra.Command {
	rootCmdTemplate := &cobra.Command{
		Use:   "fail2ban-dashboard",
		Short: "Start the fail2ban dashboard server",
		Long:  fmt.Sprintf("fail2ban-dashboard %s (%s) provides a web-based dashboard for monitoring fail2ban bans and jails", Version, GitHash),
		Run:   serve,
	}

	serveCmdTemplate := &cobra.Command{
		Use:   "serve",
		Short: "Start the fail2ban dashboard server (default)",
		Long:  fmt.Sprintf("Start the fail2ban dashboard server %s (%s) provides a web-based dashboard for monitoring fail2ban bans and jails", Version, GitHash),
		Run:   serve,
	}

	versionCmdTemplate := &cobra.Command{
		Use:   "version",
		Short: "Print the version number and git hash",
		Long:  "Print the version number and git hash",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("fail2ban-dashboard %s (%s)\n", Version, GitHash)
		},
	}

	// Config setup
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/fail2ban-dashboard/")
	viper.AddConfigPath("$HOME/.config/fail2ban-dashboard")

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			fmt.Printf("Could not parse config file: %s\n", err)
			os.Exit(1)
		}
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix("F2BD")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	// Attach flags
	addGlobalFlags(rootCmdTemplate)
	addGlobalFlags(serveCmdTemplate)
	addServeFlags(rootCmdTemplate)
	addServeFlags(serveCmdTemplate)

	// PreRun hook to bind flags dynamically for whichever command executes
	bindFlagsHook := func(cmd *cobra.Command, args []string) error {
		return viper.BindPFlags(cmd.Flags())
	}

	rootCmdTemplate.PreRunE = bindFlagsHook
	serveCmdTemplate.PreRunE = bindFlagsHook

	rootCmdTemplate.AddCommand(versionCmdTemplate)
	rootCmdTemplate.AddCommand(serveCmdTemplate)

	return rootCmdTemplate
}

func addGlobalFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.StringP("cache-dir", "c", "", "directory to cache GeoIP data, also F2BD_CACHE_DIR (default current working directory)")
	flags.StringP("socket", "s", "/var/run/fail2ban/fail2ban.sock", "location of the fail2ban socket, also F2BD_SOCKET")
	flags.String("log-level", "info", "log level (trace, debug, info, warn, error), also F2BD_LOG_LEVEL")
	flags.Bool("skip-version-check", false, "skip fail2ban version check (use at your own risk), also F2BD_SKIP_VERSION_CHECK")
	flags.Bool("scheduled-geoip-download", true, "will keep GeoIP cache update even without accessing the dashboard, also F2BD_SCHEDULED_GEOIP_DOWNLOAD")
	flags.Int("refresh-seconds", 30, "fail2ban data refresh in seconds (value from 10 to 600), also F2BD_REFRESH_SECONDS")
}

func addServeFlags(cmd *cobra.Command) {
	flags := cmd.Flags()

	flags.StringP("address", "a", "127.0.0.1:3000", "address to serve the dashboard on, also F2BD_ADDRESS")
	flags.String("auth-user", "", "username for basic auth, also F2BD_AUTH_USER")
	flags.String("auth-password", "", "password for basic auth, also F2BD_AUTH_PASSWORD")
	flags.Bool("trust-proxy-headers", false, "trust proxy headers like X-Forwarded-For, also F2BD_TRUST_PROXY_HEADERS")
	flags.String("base-path", "/", "base path of the application, also F2BD_BASE_PATH")
	flags.BoolP("metrics", "m", false, "will provide metrics endpoint, also F2BD_METRICS")
	flags.String("metrics-address", "127.0.0.1:9100", "address to make metrics available, also F2BD_METRICS_ADDRESS")
	flags.String("oauth2-client-id", "", "OAuth2 client identifier, also F2BD_OAUTH2_CLIENT_ID")
	flags.String("oauth2-auth-url", "", "OAuth2 authentication URL, also F2BD_OAUTH2_AUTH_URL")
	flags.String("oauth2-token-url", "", "OAuth2 token URL, also F2BD_OAUTH2_TOKEN_URL")
	flags.String("oauth2-redirect-url", "", "OAuth2 redirect URL, also F2BD_OAUTH2_REDIRECT_URL")
	flags.Int("oauth2-timeout-minutes", 30, "OAuth2 timeout minutes, also F2BD_OAUTH2_TIMEOUT_MINUTES")
}

func main() {
	rootCmd := setupRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
}

func serve(_ *cobra.Command, _ []string) {
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

	// OAuth2
	oauth2ClientId := viper.GetString("oauth2-client-id")
	oauth2AuthURL := viper.GetString("oauth2-auth-url")
	oauth2TokenURL := viper.GetString("oauth2-token-url")
	oauth2RedirectURL := viper.GetString("oauth2-redirect-url")
	oauth2TimeoutMinutes := viper.GetInt("oauth2-timeout-minutes")

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
	dashboardApp := fiber.New(fiber.Config{})

	configuration := &config.Configuration{
		Address:              address,
		AuthUser:             user,
		AuthPassword:         password,
		BasePath:             basePath,
		TrustProxyHeaders:    trustProxyHeaders,
		Fail2BanVersion:      fail2banVersion,
		Version:              Version,
		OAuth2ClientID:       oauth2ClientId,
		OAuth2AuthURL:        oauth2AuthURL,
		OAuth2TokenURL:       oauth2TokenURL,
		OAuth2RedirectURL:    oauth2RedirectURL,
		OAuth2TimeoutMinutes: oauth2TimeoutMinutes,
	}

	if metricsEnabled {
		metricConfiguration := &metrics.Configuration{
			Address:         metricsAddress,
			Fail2BanVersion: fail2banVersion,
			Version:         Version,
		}
		if address != metricsAddress {
			metricsApp := fiber.New(fiber.Config{})

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
