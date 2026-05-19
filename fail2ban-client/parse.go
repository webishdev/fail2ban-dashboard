package fail2ban_client

import (
	"errors"
	"net"
	"regexp"
	"time"

	"github.com/gofiber/fiber/v2/log"
)

var banRegex = regexp.MustCompile(`^(\S+)[ \t]+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \+ (-?\d+) = (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$`)

type parsedEntry struct {
	ipAddress      string
	currentPenalty string
	bannedAt       time.Time
	banEndsAt      time.Time
}

func parse(entry string) (*parsedEntry, error) {
	matches := banRegex.FindStringSubmatch(entry)
	if matches == nil {
		log.Errorf("GetBanned: Failed to parse ban entry: %s", entry)
		return nil, errors.New("could not parse banned IPs entry")
	}

	layout := "2006-01-02 15:04:05" // reference layout

	bannedAt, bannedAtErr := time.Parse(layout, matches[2])
	if bannedAtErr != nil {
		return nil, bannedAtErr
	}

	banEndsAt, banEndsAtErr := time.Parse(layout, matches[4])
	if banEndsAtErr != nil {
		return nil, banEndsAtErr
	}

	ipAddress := matches[1]

	if net.ParseIP(ipAddress) == nil {
		return nil, errors.New("invalid IP address in banned IPs entry")
	}

	result := &parsedEntry{
		ipAddress:      ipAddress,
		currentPenalty: matches[3],
		bannedAt:       bannedAt,
		banEndsAt:      banEndsAt,
	}

	return result, nil
}
