package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/webishdev/fail2ban-dashboard/config"
	"golang.org/x/oauth2"
)

func TestValidateOAuth2Config(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Configuration
		want    bool
		wantErr bool
	}{
		{
			name: "All empty",
			cfg: &config.Configuration{
				OAuth2ClientID:    "",
				OAuth2AuthURL:     "",
				OAuth2TokenURL:    "",
				OAuth2RedirectURL: "",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "All set",
			cfg: &config.Configuration{
				OAuth2ClientID:    "id",
				OAuth2AuthURL:     "auth",
				OAuth2TokenURL:    "token",
				OAuth2RedirectURL: "redirect",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "Partially set",
			cfg: &config.Configuration{
				OAuth2ClientID:    "id",
				OAuth2AuthURL:     "",
				OAuth2TokenURL:    "token",
				OAuth2RedirectURL: "redirect",
			},
			want:    true,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateOAuth2Config(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOAuth2Config() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ValidateOAuth2Config() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetOAuth2Config(t *testing.T) {
	cfg := &config.Configuration{
		OAuth2ClientID:    "id",
		OAuth2AuthURL:     "https://auth.example.com",
		OAuth2TokenURL:    "https://token.example.com",
		OAuth2RedirectURL: "https://redirect.example.com/",
	}
	basePath := "/dashboard/"
	wantRedirectURL := "https://redirect.example.com/dashboard/oauth2_callback"

	got := GetOAuth2Config(cfg, basePath)

	if got.ClientID != cfg.OAuth2ClientID {
		t.Errorf("GetOAuth2Config() ClientID = %v, want %v", got.ClientID, cfg.OAuth2ClientID)
	}
	if got.Endpoint.AuthURL != cfg.OAuth2AuthURL {
		t.Errorf("GetOAuth2Config() AuthURL = %v, want %v", got.Endpoint.AuthURL, cfg.OAuth2AuthURL)
	}
	if got.RedirectURL != wantRedirectURL {
		t.Errorf("GetOAuth2Config() RedirectURL = %v, want %v", got.RedirectURL, wantRedirectURL)
	}
}

func TestGenerateRandomState(t *testing.T) {
	s1 := generateRandomState()
	s2 := generateRandomState()
	if s1 == s2 {
		t.Errorf("generateRandomState() returned same state")
	}
	if len(s1) == 0 {
		t.Errorf("generateRandomState() returned empty string")
	}
}

func TestLogout(t *testing.T) {
	app := fiber.New()
	store := session.NewStore(session.Config{})
	basePath := "/"

	app.Get("/logout", func(c fiber.Ctx) error {
		return Logout(c, store, basePath)
	})

	req := httptest.NewRequest("GET", "/logout", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != 303 {
		t.Errorf("Logout() expected status 303, got %v", resp.StatusCode)
	}
}

func TestRedirectToLogin(t *testing.T) {
	app := fiber.New()
	store := session.NewStore(session.Config{})
	basePath := "/"

	app.Get("/protected", func(c fiber.Ctx) error {
		return RedirectToLogin(c, store, basePath)
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, _ := app.Test(req)
	if resp.StatusCode != 303 {
		t.Errorf("RedirectToLogin() expected status 303, got %v", resp.StatusCode)
	}
}

func TestCreateOAuth2Middleware(t *testing.T) {
	app := fiber.New()
	store := session.NewStore(session.Config{})
	basePath := "/"

	// Add the middleware
	app.Use(CreateOAuth2Middleware(store, basePath))

	app.Get("/protected", func(c fiber.Ctx) error {
		return c.SendString("ok")
	})

	req := httptest.NewRequest("GET", "/protected", nil)
	resp, _ := app.Test(req)
	// Expected to redirect to login because not authenticated
	if resp.StatusCode != 303 {
		t.Errorf("CreateOAuth2Middleware() expected status 303, got %v", resp.StatusCode)
	}
}

func TestCreateOAuth2CallbackHandler(t *testing.T) {
	// Mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"mock_token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	app := fiber.New()
	store := session.NewStore(session.Config{})

	// Add middleware to set session state
	app.Use(func(c fiber.Ctx) error {
		sess, _ := store.Get(c)
		sess.Set("oauth_state", "test-state")
		sess.Save()
		return c.Next()
	})

	oauthConfig := &oauth2.Config{
		ClientID: "client-id",
		Endpoint: oauth2.Endpoint{
			TokenURL: ts.URL,
		},
	}
	app.Get("/oauth2_callback", CreateOAuth2CallbackHandler(store, oauthConfig))

	req := httptest.NewRequest("GET", "/oauth2_callback?state=test-state&code=test-code", nil)
	// Need to handle session cookie if needed, but app.Test should handle cookies if properly configured
	resp, _ := app.Test(req)

	// It redirects to "/"
	if resp.StatusCode != 303 {
		t.Errorf("CreateOAuth2CallbackHandler() expected status 303, got %v", resp.StatusCode)
	}
}
