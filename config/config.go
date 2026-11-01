package config

import "slices"

type Configuration struct {
	Address              string
	AuthUser             string
	AuthPassword         string
	BasePath             string
	TrustProxyHeaders    bool
	Fail2BanVersion      string
	Version              string
	OAuth2ClientID       string
	OAuth2AuthURL        string
	OAuth2TokenURL       string
	OAuth2RedirectURL    string
	OAuth2TimeoutMinutes int
	AllowBanAll          bool
	AllowUnbanAll        bool
	AllowBanJails        []string
	AllowUnbanJails      []string
}

// CanBan reports whether banning addresses is allowed for the given jail.
func (c *Configuration) CanBan(jailName string) bool {
	return c.AllowBanAll || slices.Contains(c.AllowBanJails, jailName)
}

// CanUnban reports whether unbanning addresses is allowed for the given jail.
func (c *Configuration) CanUnban(jailName string) bool {
	return c.AllowUnbanAll || slices.Contains(c.AllowUnbanJails, jailName)
}

// HasBanActions reports whether any ban or unban action is enabled.
func (c *Configuration) HasBanActions() bool {
	return c.AllowBanAll || c.AllowUnbanAll || len(c.AllowBanJails) > 0 || len(c.AllowUnbanJails) > 0
}
