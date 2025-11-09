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

var supportedVersions = []string{"1.1.0"}

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

		fmt.Printf("fail2ban version found: %s\n", detectedFail2banVersion)

		versionIsOk := false
		for _, supportedVersion := range supportedVersions {
			if supportedVersion == detectedFail2banVersion {
				versionIsOk = true
			}
		}
		if !versionIsOk {
			fmt.Printf("fail2ban version %s not supported\n", detectedFail2banVersion)
			os.Exit(1)
		}

		fail2banVersion = detectedFail2banVersion
	}

	dataStore := store.NewDataStore(f2bc)

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

	geoIP := geoip.NewGeoIP(absolutCacheDir)

	configuration := &server.Configuration{
		Address:      address,
		AuthUser:     user,
		AuthPassword: password,
	}

	serveError := server.Serve(Version, fail2banVersion, dataStore, geoIP, configuration)
	if serveError != nil {
		fmt.Printf("Could not start server: %s\n", serveError)
		os.Exit(1)
	}
}
