package main

import (
	"fmt"
	"os"

	"github.com/gofiber/fiber/v2/log"
	"github.com/spf13/cobra"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/geoip"
	"github.com/webishdev/fail2ban-dashboard/server"
	"github.com/webishdev/fail2ban-dashboard/store"
)

var Version = "development"
var GitHash = "none"

var supportedVersions = []string{"1.1.0"}

var port int

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
	rootCmd.Flags().IntVarP(&port, "port", "p", 3000, "Port to serve the dashboard on")
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) {
	fmt.Printf("This is fail2ban-dashboard %s (%s)\n", Version, GitHash)

	socketPath := "/var/run/fail2ban/fail2ban.sock"

	f2bc, socketError := client.NewFail2BanClient(socketPath)

	var fail2banVersion = "unknown"

	if socketError != nil {
		log.Infof("Could not connect to fail2ban socket at %s", socketPath)
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

	geoIP := geoip.NewGeoIP()

	serveError := server.Serve(Version, fail2banVersion, dataStore, geoIP, port)
	if serveError != nil {
		fmt.Printf("Could not start server: %s\n", serveError)
		os.Exit(1)
	}
}
