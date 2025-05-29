package server

import (
	_ "embed"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/geoip"
	"github.com/webishdev/fail2ban-dashboard/store"
	"html/template"
	"sort"
	"strings"
	"time"
)

//go:embed resources/css/daisyui@5.css
var daisyUiCSSFile []byte

//go:embed resources/css/main.css
var mainCSSFile []byte

//go:embed resources/js/browser@4.js
var tailwindJSFile []byte

//go:embed resources/images/favicon.ico
var faviconICOFile []byte

//go:embed resources/index.html
var indexHtml []byte

//go:embed resources/jailcard.html
var jailCardHtml []byte

//go:embed resources/banned.html
var bannedHtml []byte

type indexData struct {
	Version         string
	Fail2BanVersion string
	Jails           []store.Jail
	HasBanned       bool
	Banned          []client.BanEntry
	CountryCodes    map[string]string
}

func Serve(version string, fail2banVersion string, store *store.DataStore, geoIP *geoip.GeoIP) error {

	templateFunctions := template.FuncMap{
		"safe": func(s string) template.URL {
			safe := template.URL(s)
			return safe
		},
		"time": func(t time.Time) string {
			return formatTime(t)
		},
	}

	indexTemplate, indexTemplateError := template.New("index").Funcs(templateFunctions).Parse(string(indexHtml))
	if indexTemplateError != nil {
		return indexTemplateError
	}

	// value not needed in code as it is used in the index template
	_, jailCardTemplateError := indexTemplate.New("jailCard").Parse(string(jailCardHtml))
	if jailCardTemplateError != nil {
		return jailCardTemplateError
	}

	// value not needed in code as it is used in the index template
	_, bannedTemplateError := indexTemplate.New("banned").Parse(string(bannedHtml))
	if bannedTemplateError != nil {
		return bannedTemplateError
	}

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	app.Get("images/favicon.ico", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "image/vnd.microsoft.icon")
		return c.Send(faviconICOFile)
	})

	app.Get("css/main.css", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/css")
		return c.Send(mainCSSFile)
	})

	app.Get("css/daisyui@5.css", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/css")
		return c.Send(daisyUiCSSFile)
	})

	app.Get("js/browser@4.js", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJavaScript)
		return c.Send(tailwindJSFile)
	})

	app.Get("/", func(c *fiber.Ctx) error {
		log.Infof("Access banned overview at %s%s", c.BaseURL(), c.OriginalURL())
		jails := store.GetJails()

		banned := make([]client.BanEntry, 0)
		for _, jail := range jails {
			banned = append(banned, jail.BannedEntries...)
		}

		countryCodes := make(map[string]string)

		for index, ban := range banned {
			countryCode, exists := geoIP.Lookup(ban.Address)
			if exists {
				ban.CountryCode = countryCode
				countryCodes[countryCode] = Flags[countryCode]
			} else {
				ban.CountryCode = "unknown"
			}
			banned[index] = ban
		}

		sort.Slice(banned, func(i, j int) bool {
			return banned[i].BanEndsAt.Before(banned[j].BanEndsAt)
		})

		data := &indexData{
			Version:         version,
			Fail2BanVersion: fail2banVersion,
			Jails:           jails,
			HasBanned:       len(banned) > 0,
			Banned:          banned,
			CountryCodes:    countryCodes,
		}

		var sb strings.Builder
		err := indexTemplate.Execute(&sb, data)
		if err != nil {
			return err
		}
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		return c.SendString(sb.String())
	})

	store.Start()

	return app.Listen(":3000")
}

func formatTime(t time.Time) string {
	now := time.Now()

	// Truncate to remove time portion for day comparison
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	target := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())

	daysDiff := int(target.Sub(today).Hours() / 24)

	switch daysDiff {
	case 0:
		return t.Format("15:04:05") // Today
	case -1, 1:
		return t.Format("2006.01.02 15:04:05") // Yesterday or Tomorrow
	default:
		return t.Format("2006.01.02") // Other days
	}
}
