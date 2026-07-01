package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/log"
	"github.com/gofiber/fiber/v3/middleware/session"
	"golang.org/x/oauth2"
)

func CreateOAuth2Middleware(sessionStore *session.Store, oauthConfig *oauth2.Config) fiber.Handler {
	return func(c fiber.Ctx) error {
		sess, _ := sessionStore.Get(c)
		originalURL := c.OriginalURL()

		// 1. Check if authenticated or just the callback URL is called
		if sess.Get("authenticated") != nil || strings.HasPrefix(originalURL, "/callback") {
			return c.Next()
		}

		// 2. Not authenticated: Prepare to redirect to IdP
		state := generateRandomState()
		sess.Set("oauth_state", state)
		sess.Set("return_to", originalURL)
		err := sess.Save()
		if err != nil {
			return err
		}

		authURL := oauthConfig.AuthCodeURL(state)
		return c.Redirect().To(authURL)
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

		sess.Set("authenticated", "authenticated_user") // Replace with actual user ID

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

func generateRandomState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random state: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)
}
