package config

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
}
