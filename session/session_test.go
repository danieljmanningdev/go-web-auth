package session

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if token == "" {
		t.Fatal("expected generated token")
	}
}

func TestGenerateTokenProducesUniqueTokens(t *testing.T) {
	first, err := GenerateToken()
	if err != nil {
		t.Fatalf("generate first token: %v", err)
	}

	second, err := GenerateToken()
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}

	if first == second {
		t.Fatal("expected generated session tokens to differ")
	}
}

func TestHashToken(t *testing.T) {
	first := HashToken("test-session-token")
	second := HashToken("test-session-token")

	if first == "" {
		t.Fatal("expected token hash")
	}

	if first != second {
		t.Fatal("expected identical tokens to produce identical hashes")
	}

	if first == "test-session-token" {
		t.Fatal("expected hash to differ from raw token")
	}
}

func TestDifferentTokensProduceDifferentHashes(t *testing.T) {
	first := HashToken("first-token")
	second := HashToken("second-token")

	if first == second {
		t.Fatal("expected different tokens to produce different hashes")
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.CookieName != "session" {
		t.Fatalf(
			"expected cookie name session, got %q",
			config.CookieName,
		)
	}

	if config.Path != "/" {
		t.Fatalf(
			"expected cookie path /, got %q",
			config.Path,
		)
	}

	if !config.Secure {
		t.Fatal("expected secure cookies by default")
	}

	if config.SameSite != http.SameSiteLaxMode {
		t.Fatalf(
			"expected SameSite Lax, got %d",
			config.SameSite,
		)
	}

	if config.MaxAge != 24*time.Hour {
		t.Fatalf(
			"expected max age 24h, got %s",
			config.MaxAge,
		)
	}
}

func TestSetCookie(t *testing.T) {
	config := DefaultConfig()
	config.Secure = false

	rec := httptest.NewRecorder()

	SetCookie(
		rec,
		config,
		"example-token",
	)

	result := rec.Result()
	defer result.Body.Close()

	cookies := result.Cookies()

	if len(cookies) != 1 {
		t.Fatalf(
			"expected 1 cookie, got %d",
			len(cookies),
		)
	}

	cookie := cookies[0]

	if cookie.Name != config.CookieName {
		t.Fatalf(
			"expected cookie name %q, got %q",
			config.CookieName,
			cookie.Name,
		)
	}

	if cookie.Value != "example-token" {
		t.Fatalf(
			"expected token %q, got %q",
			"example-token",
			cookie.Value,
		)
	}

	if !cookie.HttpOnly {
		t.Fatal("expected HttpOnly cookie")
	}

	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf(
			"expected SameSite Lax, got %d",
			cookie.SameSite,
		)
	}
}

func TestTokenFromRequest(t *testing.T) {
	config := DefaultConfig()

	req := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	req.AddCookie(&http.Cookie{
		Name:  config.CookieName,
		Value: "example-token",
	})

	token, err := TokenFromRequest(req, config)
	if err != nil {
		t.Fatalf("read session token: %v", err)
	}

	if token != "example-token" {
		t.Fatalf(
			"expected token %q, got %q",
			"example-token",
			token,
		)
	}
}

func TestTokenFromRequestReturnsErrNoSession(t *testing.T) {
	config := DefaultConfig()

	req := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	_, err := TokenFromRequest(req, config)

	if !errors.Is(err, ErrNoSession) {
		t.Fatalf(
			"expected ErrNoSession, got %v",
			err,
		)
	}
}

func TestClearCookie(t *testing.T) {
	config := DefaultConfig()
	config.Secure = false

	rec := httptest.NewRecorder()

	ClearCookie(
		rec,
		config,
	)

	result := rec.Result()
	defer result.Body.Close()

	cookies := result.Cookies()

	if len(cookies) != 1 {
		t.Fatalf(
			"expected 1 cookie, got %d",
			len(cookies),
		)
	}

	cookie := cookies[0]

	if cookie.Name != config.CookieName {
		t.Fatalf(
			"expected cookie name %q, got %q",
			config.CookieName,
			cookie.Name,
		)
	}

	if cookie.Value != "" {
		t.Fatalf(
			"expected empty cookie value, got %q",
			cookie.Value,
		)
	}

	if cookie.MaxAge >= 0 {
		t.Fatalf(
			"expected negative MaxAge, got %d",
			cookie.MaxAge,
		)
	}
}
