package main

import (
	"fmt"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
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

	f2bc, err := client.NewFail2BanClient(socketPath)

	if err != nil {
		panic(err)
	}

	version, err := f2bc.GetVersion()

	if err != nil {
		panic(err)
	}

	fmt.Printf("fail2ban version found: %s\n", version)

	versionIsOk := false
	for _, supportedVersion := range supportedVersions {
		if supportedVersion == version {
			versionIsOk = true
		}
	}
	if !versionIsOk {
		fmt.Printf("fail2ban version %s not supported\n", version)
		os.Exit(1)
	}

	dataStore := store.NewDataStore(f2bc)

	err = server.Serve(dataStore)
	if err != nil {
		panic(err)
	}
}
