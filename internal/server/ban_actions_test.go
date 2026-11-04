package server

import (
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/webishdev/fail2ban-dashboard/internal/client"
	"github.com/webishdev/fail2ban-dashboard/internal/config"
	"github.com/webishdev/fail2ban-dashboard/internal/models"
	"github.com/webishdev/fail2ban-dashboard/internal/store"
)

var _ client.Client = (*mockClient)(nil)

// mockClient provides empty jails and records ban actions
type mockClient struct {
	jailNames   []string
	actionError error
	banned      []string
	unbanned    []string
}

func (m *mockClient) GetVersion() (string, error) { return "1.1.0", nil }

func (m *mockClient) GetJailNames() ([]string, error) { return m.jailNames, nil }

func (m *mockClient) GetJailInfo(string) (*models.JailInfo, error) {
	return &models.JailInfo{}, nil
}

func (m *mockClient) GetBanned(jailName string) (*models.JailEntry, error) {
	return &models.JailEntry{Name: jailName}, nil
}

func (m *mockClient) BanIP(jailName string, address string) error {
	if m.actionError != nil {
		return m.actionError
	}
	m.banned = append(m.banned, jailName+"/"+address)
	return nil
}

func (m *mockClient) UnbanIP(jailName string, address string) error {
	if m.actionError != nil {
		return m.actionError
	}
	m.unbanned = append(m.unbanned, jailName+"/"+address)
	return nil
}

var csrfTokenPattern = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

func createBanTestApp(t *testing.T, f2bc *mockClient, configuration *config.Configuration) *fiber.App {
	t.Helper()
	dataStore := store.NewDataStore(f2bc, 600)
	if err := dataStore.Refresh(); err != nil {
		t.Fatalf("Failed to refresh data store: %v", err)
	}
	configuration.BasePath = "/"
	app := fiber.New()
	if err := RegisterDashboardEndpoints(app, dataStore, nil, configuration); err != nil {
		t.Fatalf("Failed to register endpoints: %v", err)
	}
	return app
}

func getPage(t *testing.T, app *fiber.App, target string) (string, []*http.Cookie) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest(fiber.MethodGet, target, nil))
	if err != nil {
		t.Fatalf("Failed to request %s: %v", target, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	return string(body), resp.Cookies()
}

func postForm(t *testing.T, app *fiber.App, target string, form url.Values, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationForm)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to post %s: %v", target, err)
	}
	return resp
}

// postWithToken loads the jail page to obtain a CSRF token and submits the form with it
func postWithToken(t *testing.T, app *fiber.App, jail string, action string, address string) *http.Response {
	t.Helper()
	body, cookies := getPage(t, app, "/"+jail)
	match := csrfTokenPattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("No CSRF token found on /%s", jail)
	}
	form := url.Values{"_csrf": {match[1]}, "address": {address}}
	return postForm(t, app, "/"+jail+"/"+action, form, cookies)
}

func TestDetailPageShowsBanButtonOnlyWhenAllowed(t *testing.T) {
	f2bc := &mockClient{jailNames: []string{"sshd", "postfix"}}
	app := createBanTestApp(t, f2bc, &config.Configuration{AllowBanJails: []string{"sshd", "doesnotexist"}})

	sshd, _ := getPage(t, app, "/sshd")
	if !strings.Contains(sshd, "ban_modal") || !strings.Contains(sshd, `action="/sshd/ban"`) {
		t.Error("Expected ban dialog on sshd page")
	}

	postfix, _ := getPage(t, app, "/postfix")
	if strings.Contains(postfix, "ban_modal") {
		t.Error("Did not expect ban dialog on postfix page")
	}
}

func TestDetailPageShowsUnbanDialogOnlyWhenAllowed(t *testing.T) {
	f2bc := &mockClient{jailNames: []string{"sshd", "postfix"}}
	app := createBanTestApp(t, f2bc, &config.Configuration{AllowUnbanJails: []string{"sshd"}})

	sshd, _ := getPage(t, app, "/sshd")
	if !strings.Contains(sshd, "unban_modal") || !strings.Contains(sshd, `action="/sshd/unban"`) {
		t.Error("Expected unban dialog on sshd page")
	}
	if strings.Contains(sshd, "confirm(") {
		t.Error("Did not expect a JavaScript confirm dialog")
	}

	postfix, _ := getPage(t, app, "/postfix")
	if strings.Contains(postfix, "unban_modal") {
		t.Error("Did not expect unban dialog on postfix page")
	}
}

func TestBanEndpointsNotRegisteredWithoutFlags(t *testing.T) {
	f2bc := &mockClient{jailNames: []string{"sshd"}}
	app := createBanTestApp(t, f2bc, &config.Configuration{})

	page, _ := getPage(t, app, "/sshd")
	if strings.Contains(page, "ban_modal") || strings.Contains(page, "_csrf") {
		t.Error("Did not expect ban controls without flags")
	}

	resp := postForm(t, app, "/sshd/ban", url.Values{"address": {"192.0.2.1"}}, nil)
	if resp.StatusCode == fiber.StatusSeeOther || len(f2bc.banned) > 0 {
		t.Errorf("Expected ban to be rejected, got status %d", resp.StatusCode)
	}
}

func TestBanAndUnbanActions(t *testing.T) {
	tests := []struct {
		name         string
		action       string
		jail         string
		address      string
		actionError  error
		wantStatus   int
		wantLocation string
		wantFlash    string
		wantBanned   []string
		wantUnbanned []string
	}{
		{
			name:         "ban IPv4",
			action:       "ban",
			jail:         "sshd",
			address:      "192.0.2.1",
			wantStatus:   fiber.StatusSeeOther,
			wantLocation: "/sshd",
			wantFlash:    "banned",
			wantBanned:   []string{"sshd/192.0.2.1"},
		},
		{
			name:         "ban IPv6 uses canonical form",
			action:       "ban",
			jail:         "sshd",
			address:      " 2001:DB8:0::1 ",
			wantStatus:   fiber.StatusSeeOther,
			wantLocation: "/sshd",
			wantFlash:    "banned",
			wantBanned:   []string{"sshd/2001:db8::1"},
		},
		{
			name:         "unban",
			action:       "unban",
			jail:         "sshd",
			address:      "192.0.2.1",
			wantStatus:   fiber.StatusSeeOther,
			wantLocation: "/sshd",
			wantFlash:    "unbanned",
			wantUnbanned: []string{"sshd/192.0.2.1"},
		},
		{
			name:         "invalid address",
			action:       "ban",
			jail:         "sshd",
			address:      "not-an-ip",
			wantStatus:   fiber.StatusSeeOther,
			wantLocation: "/sshd",
			wantFlash:    "invalid",
		},
		{
			name:         "address with zone",
			action:       "ban",
			jail:         "sshd",
			address:      "fe80::1%eth0",
			wantStatus:   fiber.StatusSeeOther,
			wantLocation: "/sshd",
			wantFlash:    "invalid",
		},
		{
			name:         "fail2ban error",
			action:       "ban",
			jail:         "sshd",
			address:      "192.0.2.1",
			actionError:  errors.New("failed"),
			wantStatus:   fiber.StatusSeeOther,
			wantLocation: "/sshd",
			wantFlash:    "failed",
		},
		{
			name:       "action not allowed for jail",
			action:     "unban",
			jail:       "postfix",
			address:    "192.0.2.1",
			wantStatus: fiber.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f2bc := &mockClient{jailNames: []string{"sshd", "postfix"}, actionError: tt.actionError}
			app := createBanTestApp(t, f2bc, &config.Configuration{
				AllowBanAll:     true,
				AllowUnbanJails: []string{"sshd"},
			})

			resp := postWithToken(t, app, tt.jail, tt.action, tt.address)

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("Expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}
			if location := resp.Header.Get(fiber.HeaderLocation); location != tt.wantLocation {
				t.Errorf("Expected location %q, got %q", tt.wantLocation, location)
			}
			if tt.wantFlash != "" {
				page := followRedirect(t, app, resp)
				if !strings.Contains(page, `data-status="`+tt.wantFlash+`"`) {
					t.Errorf("Expected %q result on the jail page", tt.wantFlash)
				}
			}
			if strings.Join(f2bc.banned, ",") != strings.Join(tt.wantBanned, ",") {
				t.Errorf("Expected banned %v, got %v", tt.wantBanned, f2bc.banned)
			}
			if strings.Join(f2bc.unbanned, ",") != strings.Join(tt.wantUnbanned, ",") {
				t.Errorf("Expected unbanned %v, got %v", tt.wantUnbanned, f2bc.unbanned)
			}
		})
	}
}

// followRedirect requests the redirect location with the cookies of the response, like a browser would
func followRedirect(t *testing.T, app *fiber.App, resp *http.Response) string {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodGet, resp.Header.Get(fiber.HeaderLocation), nil)
	for _, cookie := range resp.Cookies() {
		req.AddCookie(cookie)
	}
	redirected, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to follow redirect: %v", err)
	}
	body, err := io.ReadAll(redirected.Body)
	if err != nil {
		t.Fatalf("Failed to read body: %v", err)
	}
	return string(body)
}

func TestBanResultShownOnlyOnce(t *testing.T) {
	f2bc := &mockClient{jailNames: []string{"sshd"}}
	app := createBanTestApp(t, f2bc, &config.Configuration{AllowBanAll: true})

	resp := postWithToken(t, app, "sshd", "ban", "2001:db8::1")

	var flashCookie *http.Cookie
	for _, cookie := range resp.Cookies() {
		if cookie.Name == fiber.FlashCookieName {
			flashCookie = cookie
		}
	}
	if flashCookie == nil {
		t.Fatal("Expected flash cookie on redirect")
	}
	if strings.Contains(resp.Header.Get(fiber.HeaderLocation), "status") {
		t.Errorf("Did not expect status in location %q", resp.Header.Get(fiber.HeaderLocation))
	}

	// first request after the redirect shows the result and expires the flash cookie
	req := httptest.NewRequest(fiber.MethodGet, "/sshd", nil)
	req.AddCookie(flashCookie)
	first, err := app.Test(req)
	if err != nil {
		t.Fatalf("Failed to request page: %v", err)
	}
	firstBody, _ := io.ReadAll(first.Body)
	if !strings.Contains(string(firstBody), `data-status="banned"`) || !strings.Contains(string(firstBody), "2001:db8::1") {
		t.Error("Expected ban result with address on first request")
	}
	expired := false
	for _, cookie := range first.Cookies() {
		if cookie.Name == fiber.FlashCookieName && cookie.MaxAge < 0 {
			expired = true
		}
	}
	if !expired {
		t.Error("Expected flash cookie to be expired after it was shown")
	}

	// a reload or the old query parameter does not show the result again
	for _, target := range []string{"/sshd", "/sshd?status=banned"} {
		page, _ := getPage(t, app, target)
		if strings.Contains(page, "data-status=") {
			t.Errorf("Did not expect a result on %s", target)
		}
	}
}

func TestBanActionUnknownJail(t *testing.T) {
	f2bc := &mockClient{jailNames: []string{"sshd"}}
	app := createBanTestApp(t, f2bc, &config.Configuration{AllowBanAll: true})

	body, cookies := getPage(t, app, "/sshd")
	token := csrfTokenPattern.FindStringSubmatch(body)[1]

	resp := postForm(t, app, "/unknown/ban", url.Values{"_csrf": {token}, "address": {"192.0.2.1"}}, cookies)
	if resp.StatusCode != fiber.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestBanActionRequiresCSRFToken(t *testing.T) {
	f2bc := &mockClient{jailNames: []string{"sshd"}}
	app := createBanTestApp(t, f2bc, &config.Configuration{AllowBanAll: true})

	resp := postForm(t, app, "/sshd/ban", url.Values{"address": {"192.0.2.1"}}, nil)
	if resp.StatusCode != fiber.StatusForbidden {
		t.Errorf("Expected status 403, got %d", resp.StatusCode)
	}
	if len(f2bc.banned) > 0 {
		t.Error("Expected no ban without CSRF token")
	}
}

func TestBannedRowRendersUnbanButtonOnlyWhenAllowed(t *testing.T) {
	_, detailTemplate, _, err := parseTemplates(template.FuncMap{
		"safe":          func(s string) template.URL { return template.URL(s) },
		"time":          formatTime,
		"formatPenalty": func(p string) string { return p },
	})
	if err != nil {
		t.Fatalf("Failed to parse templates: %v", err)
	}

	entry := createTestBanEntry("192.0.2.1", "sshd", "600", time.Now(), time.Now().Add(time.Hour))

	for _, canUnban := range []bool{true, false} {
		var sb strings.Builder
		row := bannedRow{BanEntry: entry, CanUnban: canUnban}
		if err := detailTemplate.ExecuteTemplate(&sb, "banned", row); err != nil {
			t.Fatalf("Failed to execute template: %v", err)
		}
		hasButton := strings.Contains(sb.String(), `data-address="192.0.2.1"`)
		if hasButton != canUnban {
			t.Errorf("CanUnban=%v: expected unban button %v, got %v", canUnban, canUnban, hasButton)
		}
	}
}
