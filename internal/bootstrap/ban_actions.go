package bootstrap

import (
	"strings"

	"github.com/gofiber/fiber/v3/log"
)

func LogBanActions(allowBanAll bool, allowUnbanAll bool, allowBanJails []string, allowUnbanJails []string) {
	switch {
	case allowBanAll:
		log.Info("Banning addresses allowed for all jails")
	case len(allowBanJails) > 0:
		log.Infof("Banning addresses allowed for jails %s", strings.Join(allowBanJails, ", "))
	}
	switch {
	case allowUnbanAll:
		log.Info("Unbanning addresses allowed for all jails")
	case len(allowUnbanJails) > 0:
		log.Infof("Unbanning addresses allowed for jails %s", strings.Join(allowUnbanJails, ", "))
	}
}
