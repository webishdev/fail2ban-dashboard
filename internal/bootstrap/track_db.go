package bootstrap

import (
	"os"
	"path/filepath"

	"github.com/gofiber/fiber/v3/log"
)

const defaultTrackDBName = "fail2ban-dashboard.db"

// ResolveTrackDB returns the absolute location of the tracking database, by default in the current working directory.
func ResolveTrackDB(trackDB string) string {
	if trackDB == "" {
		dir, workingDirError := os.Getwd()
		if workingDirError != nil {
			log.Error("Could not access current working directory")
			os.Exit(1)
		}
		trackDB = filepath.Join(dir, defaultTrackDBName)
	}

	absoluteTrackDB, absolutePathError := filepath.Abs(trackDB)
	if absolutePathError != nil {
		log.Error(absolutePathError)
		os.Exit(1)
	}

	return absoluteTrackDB
}
