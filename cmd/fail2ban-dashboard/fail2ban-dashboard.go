package main

import (
	"fmt"
	"github.com/gofiber/fiber/v2/log"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/geoip"
	"github.com/webishdev/fail2ban-dashboard/server"
	"github.com/webishdev/fail2ban-dashboard/store"
	"os"
)

var Version = "development"
var GitHash = "none"

var supportedVersions = []string{"1.1.0"}

func main() {
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

	serveError := server.Serve(Version, fail2banVersion, dataStore, geoIP)
	if serveError != nil {
		fmt.Printf("Could not start server: %s\n", serveError)
		os.Exit(1)
	}
}
