package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

const tokenBytes = 32

var ErrNoSession = errors.New("session cookie not found")

type Config struct {
	CookieName string
	Path       string
	Secure     bool
	SameSite   http.SameSite
	MaxAge     time.Duration
}

func DefaultConfig() Config {
	return Config{
		CookieName: "session",
		Path:       "/",
		Secure:     true,
		SameSite:   http.SameSiteLaxMode,
		MaxAge:     24 * time.Hour,
	}
}

func GenerateToken() (string, error) {
	buffer := make([]byte, tokenBytes)

	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func SetCookie(
	w http.ResponseWriter,
	config Config,
	token string,
) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.CookieName,
		Value:    token,
		Path:     config.Path,
		HttpOnly: true,
		Secure:   config.Secure,
		SameSite: config.SameSite,
		MaxAge:   int(config.MaxAge.Seconds()),
	})
}

func TokenFromRequest(
	r *http.Request,
	config Config,
) (string, error) {
	cookie, err := r.Cookie(config.CookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", ErrNoSession
		}

		return "", err
	}

	if cookie.Value == "" {
		return "", ErrNoSession
	}

	return cookie.Value, nil
}

func ClearCookie(
	w http.ResponseWriter,
	config Config,
) {
	http.SetCookie(w, &http.Cookie{
		Name:     config.CookieName,
		Value:    "",
		Path:     config.Path,
		HttpOnly: true,
		Secure:   config.Secure,
		SameSite: config.SameSite,
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
	})
}
