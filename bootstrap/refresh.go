package bootstrap

import "github.com/gofiber/fiber/v2/log"

func ValidateRefreshSeconds(refreshSeconds int) int {
	if refreshSeconds < 10 || refreshSeconds > 600 {
		log.Warn("fail2ban data refresh must be between 10 and 600 seconds, resetting to default of 30 seconds")
		return 30
	}
	return refreshSeconds
}
