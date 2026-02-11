package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v2/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/geoip"
	"github.com/webishdev/fail2ban-dashboard/server"
	"github.com/webishdev/fail2ban-dashboard/store"
)

var Version = "development"
var GitHash = "none"

var supportedVersions = []string{"0.11.1", "0.11.2", "1.0.1", "1.0.2", "1.1.0"}

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

func init() {
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

	flags.StringP("socket", "s", "/var/run/fail2ban/fail2ban.sock", "fail2ban socket, also F2BD_SOCKET")
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

	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
}

func run(_ *cobra.Command, _ []string) {
	fmt.Printf("This is fail2ban-dashboard %s (%s)\n", Version, GitHash)

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

	// Set log level
	switch logLevel {
	case "trace":
		log.SetLevel(log.LevelTrace)
	case "debug":
		log.SetLevel(log.LevelDebug)
	case "info":
		log.SetLevel(log.LevelInfo)
	case "warn":
		log.SetLevel(log.LevelWarn)
	case "error":
		log.SetLevel(log.LevelError)
	default:
		log.SetLevel(log.LevelInfo)
		log.Warnf("Invalid log level '%s', using 'info'", logLevel)
	}

	log.Debugf("Log level set to %s", logLevel)

	if refreshSeconds < 10 || refreshSeconds > 600 {
		log.Warn("fail2ban data refresh must be between 10 and 600 seconds, resetting to default of 30 seconds")
		refreshSeconds = 30
	}

	if trustProxyHeaders {
		log.Info("Trusting proxy headers")
	}

	log.Infof("Base path set to %s", basePath)

	log.Infof("Data refresh from fail2ban set to %d seconds", refreshSeconds)

	log.Infof("Will use socket at %s for fail2ban connection", socketPath)
	f2bc, socketError := client.NewFail2BanClient(socketPath)

	var fail2banVersion = "unknown"

	if socketError != nil {
		log.Errorf("Could not connect to fail2ban socket at %s", socketPath)
	} else {
		detectedFail2banVersion, versionError := f2bc.GetVersion()

		if versionError != nil {
			panic(versionError)
		}

		log.Infof("fail2ban version found: %s\n", detectedFail2banVersion)

		versionIsOk := false
		for _, supportedVersion := range supportedVersions {
			if supportedVersion == detectedFail2banVersion {
				versionIsOk = true
			}
		}
		if !skipVersionCheck && !versionIsOk {
			log.Errorf("fail2ban version %s not supported\n", detectedFail2banVersion)
			os.Exit(1)
		} else if skipVersionCheck && !versionIsOk {
			log.Info("Skipping version check (dashboard may not work as expected)")
		} else if skipVersionCheck {
			log.Debug("Skipping version check but version is supported")
		}

		fail2banVersion = detectedFail2banVersion
	}

	dataStore := store.NewDataStore(f2bc, refreshSeconds)

	if cacheDir == "" {
		dir, workingDirError := os.Getwd()
		if workingDirError != nil {
			log.Error("Could not access current working directory")
			os.Exit(1)
		}
		cacheDir = dir
	}

	absolutCacheDir, absolutPathError := filepath.Abs(cacheDir)
	if absolutPathError != nil {
		log.Error(absolutPathError)
		os.Exit(1)
	}

	if _, statError := os.Stat(absolutCacheDir); os.IsNotExist(statError) {
		log.Infof("Creating cache directory %s", absolutCacheDir)
		if mkdirError := os.MkdirAll(absolutCacheDir, os.ModePerm); mkdirError != nil {
			log.Errorf("Cache directory could not be created at %s", absolutCacheDir)
			os.Exit(1)
		}

	}

	geoIP := geoip.NewGeoIP(absolutCacheDir, enableSchedule)

	configuration := &server.Configuration{
		Address:      address,
		AuthUser:     user,
		AuthPassword: password,
	}

	serveError := server.Serve(Version, fail2banVersion, basePath, trustProxyHeaders, dataStore, geoIP, configuration)
	if serveError != nil {
		log.Errorf("Could not start server: %s\n", serveError)
		os.Exit(1)
	}
}
