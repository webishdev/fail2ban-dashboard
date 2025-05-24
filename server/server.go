package server

import (
	_ "embed"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/store"
	"html/template"
	"sort"
	"strings"
)

//go:embed resources/css/daisyui@5.css
var cssFile []byte

//go:embed resources/js/browser@4.js
var jsFile []byte

//go:embed resources/index.html
var indexHtml []byte

//go:embed resources/jailcard.html
var jailCardHtml []byte

//go:embed resources/banned.html
var bannedHtml []byte

type indexData struct {
	Version         string
	Fail2BanVersion string
	Jails           []client.StaticJailEntry
	HasBanned       bool
	Banned          []client.BanEntry
}

func Serve(version string, fail2banVersion string, store *store.DataStore) error {
	indexTemplate, indexTemplateError := template.New("index").Parse(string(indexHtml))
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

	app := fiber.New()

	app.Get("css/daisyui@5.css", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/css")
		return c.Send(cssFile)
	})

	app.Get("js/browser@4.js", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJavaScript)
		return c.Send(jsFile)
	})

	app.Get("/", func(c *fiber.Ctx) error {
		log.Infof("Access banned overview at %s%s", c.BaseURL(), c.OriginalURL())
		jails := store.GetJails()

		banned := make([]client.BanEntry, 0)
		for _, jail := range jails {
			banned = append(banned, jail.BannedEntries...)
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
