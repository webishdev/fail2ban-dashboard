package server

import (
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"fmt"
	"html/template"
	"net"
	"path"
	"sort"
	"strconv"
	"strings"
	textTemplate "text/template"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/geoip"
	"github.com/webishdev/fail2ban-dashboard/store"
)

//go:embed resources/css/daisyui@5.css
var daisyUiCSSFile []byte

//go:embed resources/css/themes.css
var themesUiCSSFile []byte

//go:embed resources/css/main.css
var mainCSSFile []byte

//go:embed resources/js/browser@4.js
var tailwindJSFile []byte

//go:embed resources/images/favicon.ico
var faviconICOFile []byte

//go:embed resources/index.html
var indexHtml []byte

//go:embed resources/detail.html
var detailHtml []byte

//go:embed resources/partial_jailcard.html
var jailCardHtml []byte

//go:embed resources/partial_jaildetail.html
var jailDetailHtml []byte

//go:embed resources/partial_banned.html
var bannedHtml []byte

//go:embed resources/partial_head.html
var headHtml []byte

//go:embed resources/partial_header.html
var headerHtml []byte

//go:embed resources/flags.css
var flagsCss []byte

type Configuration struct {
	Address      string
	AuthUser     string
	AuthPassword string
}

type Sorted struct {
	Order string
	Class string
}

type baseData struct {
	Version         string
	Fail2BanVersion string
	BasePath        string
	CountryCodes    template.URL
	HasBanned       bool
	Banned          []client.BanEntry
}

type indexData struct {
	baseData
	BannedSum int
	Jails     []store.Jail
}

type detailData struct {
	baseData
	OrderAddress Sorted
	OrderPenalty Sorted
	OrderStarted Sorted
	OrderEnds    Sorted
	Jail         store.Jail
}

func Serve(version string, fail2banVersion string, basePath string, trustProxyHeaders bool, dataStore *store.DataStore, geoIP *geoip.GeoIP, configuration *Configuration) error {

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

	detailTemplate, detailTemplateError := template.New("detail").Funcs(templateFunctions).Parse(string(detailHtml))
	if detailTemplateError != nil {
		return detailTemplateError
	}

	flagsTemplate, flagsTemplateError := textTemplate.New("flags").Parse(string(flagsCss))
	if flagsTemplateError != nil {
		return flagsTemplateError
	}

	// value isn't needed in code as it is used in the index template
	_, indexJailCardTemplateError := indexTemplate.New("jailCard").Parse(string(jailCardHtml))
	if indexJailCardTemplateError != nil {
		return indexJailCardTemplateError
	}

	// value isn't needed in code as it is used in the index template
	_, indexBannedTemplateError := indexTemplate.New("banned").Parse(string(bannedHtml))
	if indexBannedTemplateError != nil {
		return indexBannedTemplateError
	}

	// value isn't needed in code as it is used in the index template
	_, indexHeadTemplateError := indexTemplate.New("head").Parse(string(headHtml))
	if indexHeadTemplateError != nil {
		return indexHeadTemplateError
	}

	// value isn't needed in code as it is used in the index template
	_, indexHeaderTemplateError := indexTemplate.New("header").Parse(string(headerHtml))
	if indexHeaderTemplateError != nil {
		return indexHeaderTemplateError
	}

	// value isn't needed in code as it is used in the index template
	_, detailHeadTemplateError := detailTemplate.New("head").Parse(string(headHtml))
	if detailHeadTemplateError != nil {
		return detailHeadTemplateError
	}

	// value isn't needed in code as it is used in the index template
	_, detailHeaderTemplateError := detailTemplate.New("header").Parse(string(headerHtml))
	if detailHeaderTemplateError != nil {
		return detailHeaderTemplateError
	}

	// value isn't needed in code as it is used in the index template
	_, detailJailCardTemplateError := detailTemplate.New("jailCard").Parse(string(jailCardHtml))
	if detailJailCardTemplateError != nil {
		return detailJailCardTemplateError
	}

	// value isn't needed in code as it is used in the detail template
	_, detailJailDetailTemplateError := detailTemplate.New("jailDetail").Parse(string(jailDetailHtml))
	if detailJailDetailTemplateError != nil {
		return detailJailDetailTemplateError
	}

	// value isn't needed in code as it is used in the index template
	_, detailBannedTemplateError := detailTemplate.New("banned").Parse(string(bannedHtml))
	if detailBannedTemplateError != nil {
		return detailBannedTemplateError
	}

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	if configuration.AuthUser != "" || configuration.AuthPassword != "" {
		log.Info("Basic authentication enabled")
		if configuration.AuthUser == "" {
			configuration.AuthUser = "admin"
		}
		log.Infof("Basic authentication username set to %s", configuration.AuthUser)
		if configuration.AuthPassword == "" {
			configuration.AuthPassword = rand.Text()
			log.Infof("Basic authentication password set to %s", configuration.AuthPassword)
		}

		app.Use(basicauth.New(basicauth.Config{
			Users: map[string]string{
				configuration.AuthUser: configuration.AuthPassword,
			},
		}))
	}

	cleanedBasePath := path.Clean(basePath)
	dashboard := app.Group(cleanedBasePath)

	dashboard.Get("images/favicon.ico", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "image/vnd.microsoft.icon")
		return c.Send(faviconICOFile)
	})

	dashboard.Get("css/main.css", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/css")
		return c.Send(mainCSSFile)
	})

	dashboard.Get("css/daisyui@5.css", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/css")
		return c.Send(daisyUiCSSFile)
	})

	dashboard.Get("css/themes.css", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/css")
		return c.Send(themesUiCSSFile)
	})

	dashboard.Get("css/flags.css", func(c *fiber.Ctx) error {
		codeQuery := c.Query("c")
		if codeQuery == "" {
			return c.SendStatus(fiber.StatusNotFound)
		}
		countryCodeValues := strings.Split(codeQuery, ",")

		countryCodes := make(map[string]string)

		for _, countryCode := range countryCodeValues {
			countryCodes[countryCode] = Flags[strings.ToUpper(countryCode)]
		}

		var sb strings.Builder
		err := flagsTemplate.Execute(&sb, countryCodes)
		if err != nil {
			return err
		}
		c.Set(fiber.HeaderContentType, "text/css")
		return c.SendString(sb.String())
	})

	dashboard.Get("js/browser@4.js", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJavaScript)
		return c.Send(tailwindJSFile)
	})

	dashboard.Get("/", func(c *fiber.Ctx) error {
		accessLog(trustProxyHeaders, "overview", c)
		jails := dataStore.GetJails()

		sum := 0

		banned := make([]client.BanEntry, 0)
		for _, jail := range jails {
			sum += len(jail.BannedEntries)
			banned = append(banned, jail.BannedEntries...)
		}

		countryCodes := make([]string, 0)

		for index, ban := range banned {
			countryCode, exists := geoIP.Lookup(ban.Address)
			if exists {
				ban.CountryCode = countryCode
				countryCodes = append(countryCodes, countryCode)
			} else {
				ban.CountryCode = "unknown"
			}
			banned[index] = ban
		}

		data := &indexData{
			baseData: baseData{
				Version:         version,
				Fail2BanVersion: fail2banVersion,
				BasePath:        cleanBasePathForTemplate(cleanedBasePath),
				CountryCodes:    template.URL("flags.css?c=" + strings.Join(countryCodes, ",")),
				HasBanned:       len(banned) > 0,
				Banned:          banned,
			},
			BannedSum: sum,
			Jails:     jails,
		}

		var sb strings.Builder
		err := indexTemplate.Execute(&sb, data)
		if err != nil {
			return err
		}
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		return c.SendString(sb.String())
	})

	dashboard.Get("/:jail", func(c *fiber.Ctx) error {
		jailName := c.Params("jail")
		name := fmt.Sprintf("%s details", jailName)
		accessLog(trustProxyHeaders, name, c)

		jailByName, exists := dataStore.GetJailByName(jailName)

		if !exists {
			return c.Status(404).SendString("Jail not found")
		}

		banned := make([]client.BanEntry, 0)
		banned = append(banned, jailByName.BannedEntries...)

		countryCodes := make([]string, 0)

		for index, ban := range banned {
			countryCode, exists := geoIP.Lookup(ban.Address)
			if exists {
				ban.CountryCode = countryCode
				countryCodes = append(countryCodes, countryCode)
			} else {
				ban.CountryCode = "unknown"
			}
			banned[index] = ban
		}

		sorting := c.Query("sorting", "ends")
		order := c.Query("order", "asc")

		sort.Slice(banned, sortSlice(sorting, order, banned))

		detail := &detailData{
			baseData: baseData{
				Version:         version,
				Fail2BanVersion: fail2banVersion,
				BasePath:        cleanBasePathForTemplate(cleanedBasePath),
				CountryCodes:    template.URL("flags.css?c=" + strings.Join(countryCodes, ",")),
				HasBanned:       len(banned) > 0,
				Banned:          banned,
			},
			OrderAddress: toggleSortOrder("address", sorting, order),
			OrderPenalty: toggleSortOrder("penalty", sorting, order),
			OrderStarted: toggleSortOrder("started", sorting, order),
			OrderEnds:    toggleSortOrder("ends", sorting, order),
			Jail:         jailByName,
		}

		var sb strings.Builder
		err := detailTemplate.Execute(&sb, detail)
		if err != nil {
			return err
		}
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		return c.SendString(sb.String())
	})

	dataStore.Start()

	log.Infof("Listening on address %s", configuration.Address)

	return app.Listen(configuration.Address)
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

func firstNonEmpty(def string, vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return def
}

func cleanBasePathForTemplate(basePath string) string {
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}
	return basePath
}

func accessLog(trustProxyHeaders bool, name string, c *fiber.Ctx) {
	remoteIP := c.IP()
	additionalInfo := ""
	if trustProxyHeaders {
		xff := c.Get("X-Forwarded-For")
		xri := c.Get("X-Real-Ip")
		remoteIP = firstNonEmpty(remoteIP, xff, xri)
		if xff != "" || xri != "" {
			additionalInfo += "forwarded"
		}
		log.Debugf("X-Forwarded-For: %s, X-Real-Ip: %s", xff, xri)
		if len(additionalInfo) > 0 {
			additionalInfo = fmt.Sprintf("(%s)", additionalInfo)
		}
	}
	log.Infof("Access %s at %s%s for %s %s", name, c.BaseURL(), c.OriginalURL(), remoteIP, additionalInfo)
}
