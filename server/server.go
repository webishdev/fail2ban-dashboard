package server

import (
	_ "embed"
	"encoding/binary"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/geoip"
	"github.com/webishdev/fail2ban-dashboard/store"
	"html/template"
	"net"
	"sort"
	"strconv"
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

type Sorted struct {
	Order string
	Class string
}

type indexData struct {
	Version         string
	Fail2BanVersion string
	Jails           []store.Jail
	HasBanned       bool
	Banned          []client.BanEntry
	CountryCodes    map[string]string
	OrderAddress    Sorted
	OrderJail       Sorted
	OrderPenalty    Sorted
	OrderStarted    Sorted
	OrderEnds       Sorted
}

func Serve(version string, fail2banVersion string, store *store.DataStore, geoIP *geoip.GeoIP) error {

	log.SetLevel(log.LevelInfo)

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
		log.Infof("Access banned overview at %s%s for %s", c.BaseURL(), c.OriginalURL(), c.IP())
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

		sorting := c.Query("sorting", "ends")
		order := c.Query("order", "asc")

		sort.Slice(banned, sortSlice(sorting, order, banned))

		data := &indexData{
			Version:         version,
			Fail2BanVersion: fail2banVersion,
			Jails:           jails,
			HasBanned:       len(banned) > 0,
			Banned:          banned,
			CountryCodes:    countryCodes,
			OrderAddress:    toggleSortOrder("address", sorting, order),
			OrderJail:       toggleSortOrder("jail", sorting, order),
			OrderPenalty:    toggleSortOrder("penalty", sorting, order),
			OrderStarted:    toggleSortOrder("started", sorting, order),
			OrderEnds:       toggleSortOrder("ends", sorting, order),
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

func sortSlice(sorting string, order string, banned []client.BanEntry) func(i, j int) bool {
	switch {
	case sorting == "address" && order == "desc":
		return func(i, j int) bool {
			first := ipToUint32(banned[i].Address)
			second := ipToUint32(banned[j].Address)
			return first > second
		}
	case sorting == "address" && order == "asc":
		return func(i, j int) bool {
			first := ipToUint32(banned[i].Address)
			second := ipToUint32(banned[j].Address)
			return first < second
		}
	case sorting == "jail" && order == "desc":
		return func(i, j int) bool {
			return banned[i].JailName > banned[j].JailName
		}
	case sorting == "jail" && order == "asc":
		return func(i, j int) bool {
			return banned[i].JailName < banned[j].JailName
		}
	case sorting == "penalty" && order == "desc":
		return func(i, j int) bool {
			first := penaltyToUint64(banned[i].CurrenPenalty)
			second := penaltyToUint64(banned[j].CurrenPenalty)
			return first > second
		}
	case sorting == "penalty" && order == "asc":
		return func(i, j int) bool {
			first := penaltyToUint64(banned[i].CurrenPenalty)
			second := penaltyToUint64(banned[j].CurrenPenalty)
			return first < second
		}
	case sorting == "started" && order == "desc":
		return func(i, j int) bool {
			return banned[i].BannedAt.After(banned[j].BannedAt)
		}
	case sorting == "started" && order == "asc":
		return func(i, j int) bool {
			return banned[i].BannedAt.Before(banned[j].BannedAt)
		}
	case sorting == "ends" && order == "desc":
		return func(i, j int) bool {
			return banned[i].BanEndsAt.After(banned[j].BanEndsAt)
		}
	case sorting == "ends" && order == "asc":
	default:
	}

	return func(i, j int) bool {
		return banned[i].BanEndsAt.Before(banned[j].BanEndsAt)
	}
}

func toggleSortOrder(current string, sorting string, order string) Sorted {
	if current == sorting {
		if order == "asc" {
			return Sorted{"desc", "arrow-down"}
		}
		return Sorted{"asc", "arrow-up"}
	}
	return Sorted{"asc", "arrows-up-down"}
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
		return t.Format("02.01.2006 15:04:05") // Yesterday or Tomorrow
	default:
		return t.Format("02.01.2006") // Other days
	}
}

func ipToUint32(address string) uint32 {
	ip := net.ParseIP(address)
	ip = ip.To4()
	if ip == nil {
		return 0 // or handle invalid IP
	}
	return binary.BigEndian.Uint32(ip)
}

func penaltyToUint64(penalty string) int64 {
	i64, err := strconv.ParseInt(penalty, 10, 64) // base 10, 64-bit int
	if err != nil {
		return 0
	}
	return i64
}
