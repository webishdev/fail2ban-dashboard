package bootstrap

import "github.com/gofiber/fiber/v2/log"

func ConfigureLogging(logLevel string) {
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
}
