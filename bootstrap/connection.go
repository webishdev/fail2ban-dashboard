package bootstrap

import (
	"os"

	"github.com/gofiber/fiber/v2/log"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
)

var supportedVersions = []string{"0.11.1", "0.11.2", "1.0.1", "1.0.2", "1.1.0"}

func ConnectToFail2ban(socketPath string, skipVersionCheck bool) (*client.Fail2BanClient, string) {
	log.Infof("Will use socket at %s for fail2ban connection", socketPath)
	f2bc, socketError := client.NewFail2BanClient(socketPath)

	fail2banVersion := "unknown"

	if socketError != nil {
		log.Errorf("Could not connect to fail2ban socket at %s", socketPath)
		return f2bc, fail2banVersion
	}

	detectedFail2banVersion, versionError := f2bc.GetVersion()
	if versionError != nil {
		log.Error("Could not get fail2ban version, using 'unknown'")
		os.Exit(1)
	}

	log.Infof("fail2ban version found: %s\n", detectedFail2banVersion)

	versionIsOk := false
	for _, supportedVersion := range supportedVersions {
		if supportedVersion == detectedFail2banVersion {
			versionIsOk = true
			break
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

	return f2bc, detectedFail2banVersion
}
