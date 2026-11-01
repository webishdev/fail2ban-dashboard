package client

import "github.com/webishdev/fail2ban-dashboard/models"

type Client interface {
	GetVersion() (string, error)
	GetJailNames() ([]string, error)
	GetJailInfo(jailName string) (*models.JailInfo, error)
	GetBanned(jailName string) (*models.JailEntry, error)
	BanIP(jailName string, address string) error
	UnbanIP(jailName string, address string) error
}
