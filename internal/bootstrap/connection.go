package bootstrap

import (
	"os"
	"slices"

	"github.com/gofiber/fiber/v3/log"
	"github.com/webishdev/fail2ban-dashboard/internal/client"
	fail2banclient "github.com/webishdev/fail2ban-dashboard/internal/client/fail2ban-client"
)

var supportedVersions = []string{"0.11.1", "0.11.2", "1.0.1", "1.0.2", "1.1.0", "1.1.1"}

func ConnectToFail2ban(socketPath string, skipVersionCheck bool) (client.Client, string) {
	log.Infof("Will use socket at %s for fail2ban connection", socketPath)
	f2bc, socketError := fail2banclient.NewFail2BanClient(socketPath)

	fail2banVersion := "unknown"

	if socketError != nil {
		log.Errorf("Could not connect to fail2ban socket at %s", socketPath)
		return nil, fail2banVersion
	}

	detectedFail2banVersion, versionError := f2bc.GetVersion()
	if versionError != nil {
		log.Error("Could not get fail2ban version, using 'unknown'")
		os.Exit(1)
	}

	log.Infof("fail2ban version found: %s\n", detectedFail2banVersion)

	versionIsOk := slices.Contains(supportedVersions, detectedFail2banVersion)

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
