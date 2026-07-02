package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/webishdev/fail2ban-dashboard/config"
	"golang.org/x/oauth2"
)

var CallBackEndpoint = "oauth2_callback"
var LoginEndpoint = "login"
var LogoutEndpoint = "logout"

func ValidateOAuth2Config(configuration *config.Configuration) (bool, error) {
	oauth2ValuesUsed := configuration.OAuth2ClientID != "" || configuration.OAuth2AuthURL != "" || configuration.OAuth2TokenURL != "" || configuration.OAuth2RedirectURL != ""

	if oauth2ValuesUsed && configuration.OAuth2ClientID != "" && configuration.OAuth2AuthURL != "" && configuration.OAuth2TokenURL != "" && configuration.OAuth2RedirectURL != "" {
		return oauth2ValuesUsed, nil
	}

	return oauth2ValuesUsed, errors.New("missing some OAuth2 configuration values")
}

func GetOAuth2Config(configuration *config.Configuration, basePath string) *oauth2.Config {
	redirectURL := configuration.OAuth2RedirectURL
	if strings.HasSuffix(redirectURL, "/") {
		redirectURL = strings.TrimSuffix(redirectURL, "/")
	}
	return &oauth2.Config{
		ClientID: configuration.OAuth2ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:   configuration.OAuth2AuthURL,
			TokenURL:  configuration.OAuth2TokenURL,
			AuthStyle: oauth2.AuthStyleAutoDetect,
		},
		RedirectURL: fmt.Sprintf("%s%s%s", redirectURL, basePath, CallBackEndpoint),
	}
}

func CreateOAuth2Middleware(sessionStore *session.Store, basePath string) fiber.Handler {
	return func(c fiber.Ctx) error {
		return RedirectToLogin(c, sessionStore, basePath)
	}
}

func CreateOAuth2CallbackHandler(sessionStore *session.Store, oauthConfig *oauth2.Config) func(c fiber.Ctx) error {
	return func(c fiber.Ctx) error {
		sess, err := sessionStore.Get(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("Session error")
		}

		oauthStateSession := sess.Get("oauth_state")
		oauthStateQuery := c.Query("state")

		if oauthStateSession == nil || oauthStateQuery == "" || oauthStateSession.(string) != oauthStateQuery {
			return c.Status(fiber.StatusUnauthorized).SendString("Invalid state parameter")
		}

		code := c.Query("code")
		if code == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Authorization code missing")
		}

		_, tokenErr := oauthConfig.Exchange(c.Context(), code)
		if tokenErr != nil {
			log.Errorf("Failed to exchange token: %v", err)
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to exchange token")
		}

		sess.Set("authenticated", "authenticated_user")
		sess.Set("expires_at", time.Now().Add(30*time.Minute).Unix())

		sess.Delete("oauth_state")

		if err := sess.Save(); err != nil {
			log.Errorf("Failed to save session: %v", err)
			return c.Status(fiber.StatusInternalServerError).SendString("Failed to save session")
		}

		returnTo := sess.Get("return_to")
		sess.Delete("return_to")
		sessionError := sess.Save()
		if sessionError != nil {
			return sessionError
		}

		redirectURL := "/" // Default fallback
		if returnTo != nil {
			redirectURL = returnTo.(string)
		}

		return c.Redirect().To(redirectURL)
	}
}

func Logout(c fiber.Ctx, sessionStore *session.Store, basePath string) error {
	sess, _ := sessionStore.Get(c)
	err := sess.Destroy()
	if err != nil {
		return err
	}
	return c.Redirect().To(basePath)
}

func RedirectToLogin(c fiber.Ctx, sessionStore *session.Store, basePath string) error {
	sess, _ := sessionStore.Get(c)
	originalURL := c.OriginalURL()

	parsedURL, urlParseErr := url.Parse(originalURL)
	if urlParseErr != nil {
		return urlParseErr
	}

	filename := path.Base(parsedURL.Path)

	isAuthenticated := sess.Get("authenticated")

	if strings.HasSuffix(filename, CallBackEndpoint) ||
		strings.HasSuffix(filename, ".css") ||
		strings.HasSuffix(filename, ".js") ||
		strings.HasSuffix(filename, ".png") ||
		strings.HasSuffix(filename, ".ico") {
		return c.Next()
	}

	if isAuthenticated != nil {
		expiresAt, ok := sess.Get("expires_at").(int64)
		if ok && time.Now().Unix() <= expiresAt {
			return c.Next()
		}
	}

	returnTo := sess.Get("return_to")
	if returnTo == nil {
		sess.Set("return_to", originalURL)
		err := sess.Save()
		if err != nil {
			return err
		}
	}

	return c.Redirect().To(basePath + LoginEndpoint)

}

func RedirectToOAuth(c fiber.Ctx, sessionStore *session.Store, oauthConfig *oauth2.Config) error {
	sess, _ := sessionStore.Get(c)

	// 2. Not authenticated: Prepare to redirect to IdP
	state := generateRandomState()
	codeVerifier := oauth2.GenerateVerifier()

	sess.Set("oauth_state", state)
	sess.Set("oauth_code_verifier", codeVerifier)
	err := sess.Save()
	if err != nil {
		return err
	}

	authURL := oauthConfig.AuthCodeURL(state, oauth2.S256ChallengeOption(codeVerifier))
	return c.Redirect().To(authURL)
}

func generateRandomState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random state: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)
}
