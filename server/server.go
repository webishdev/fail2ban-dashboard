package server

import (
	_ "embed"
	"fmt"
	"github.com/gofiber/fiber/v2"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/store"
	"html/template"
	"strings"
)

//go:embed resources/index.html
var indexHtml []byte

//go:embed resources/jailcard.html
var jailCardHtml []byte

type indexData struct {
	Jails []client.StaticJailEntry
}

func Serve(store *store.DataStore) error {
	indexTemplate, indexTemplateError := template.New("index").Parse(string(indexHtml))
	if indexTemplateError != nil {
		return indexTemplateError
	}

	// value not needed in code as it is used in the index template
	_, jailCardTemplateError := indexTemplate.New("jailCard").Parse(string(jailCardHtml))
	if jailCardTemplateError != nil {
		return jailCardTemplateError
	}

	app := fiber.New()

	app.Get("/", func(c *fiber.Ctx) error {
		jails := store.GetJails()

		fmt.Printf("Jails: %#v\n", jails)

		data := &indexData{
			Jails: jails,
		}

		var sb strings.Builder
		err := indexTemplate.Execute(&sb, data)
		if err != nil {
			return err
		}
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		return c.SendString(sb.String())
	})

	return app.Listen(":3000")
}
