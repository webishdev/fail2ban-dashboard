package bootstrap

import (
	"os"
	"path/filepath"

	"github.com/gofiber/fiber/v2/log"
)

func SetupCacheDirectory(cacheDir string) string {
	if cacheDir == "" {
		dir, workingDirError := os.Getwd()
		if workingDirError != nil {
			log.Error("Could not access current working directory")
			os.Exit(1)
		}
		cacheDir = dir
	}

	absoluteCacheDir, absolutePathError := filepath.Abs(cacheDir)
	if absolutePathError != nil {
		log.Error(absolutePathError)
		os.Exit(1)
	}

	if _, statError := os.Stat(absoluteCacheDir); os.IsNotExist(statError) {
		log.Infof("Creating cache directory %s", absoluteCacheDir)
		if mkdirError := os.MkdirAll(absoluteCacheDir, os.ModePerm); mkdirError != nil {
			log.Errorf("Cache directory could not be created at %s", absoluteCacheDir)
			os.Exit(1)
		}
	}

	return absoluteCacheDir
}
