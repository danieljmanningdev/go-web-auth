package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danieljmanningdev/go-web-auth/session"
)

func testConfig() Config {
	sessionConfig := session.DefaultConfig()
	sessionConfig.Secure = false

	return Config{
		Session:  sessionConfig,
		LoginURL: "/login",
	}
}

func TestAuthenticateAddsUserIDToRequest(t *testing.T) {
	config := testConfig()

	token := "example-session-token"
	expectedHash := session.HashToken(token)

	lookup := func(
		ctx context.Context,
		tokenHash string,
	) (int64, bool, error) {
		if tokenHash != expectedHash {
			t.Fatalf(
				"expected token hash %q, got %q",
				expectedHash,
				tokenHash,
			)
		}

		return 42, true, nil
	}

	next := http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		userID, ok := UserID(r)
		if !ok {
			t.Fatal("expected authenticated user")
		}

		if userID != 42 {
			t.Fatalf(
				"expected user ID 42, got %d",
				userID,
			)
		}

		w.WriteHeader(http.StatusOK)
	})

	handler := Authenticate(
		config,
		lookup,
		next,
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/dashboard",
		nil,
	)

	req.AddCookie(&http.Cookie{
		Name:  config.Session.CookieName,
		Value: token,
	})

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			rec.Code,
		)
	}
}

func TestAuthenticateAllowsAnonymousRequest(t *testing.T) {
	config := testConfig()

	lookupCalled := false

	lookup := func(
		ctx context.Context,
		tokenHash string,
	) (int64, bool, error) {
		lookupCalled = true
		return 0, false, nil
	}

	nextCalled := false

	next := http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		nextCalled = true

		if Authenticated(r) {
			t.Fatal("expected anonymous request")
		}

		w.WriteHeader(http.StatusOK)
	})

	handler := Authenticate(
		config,
		lookup,
		next,
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if lookupCalled {
		t.Fatal("expected lookup not to run without session cookie")
	}

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
}

func TestAuthenticateIgnoresUnknownSession(t *testing.T) {
	config := testConfig()

	lookup := func(
		ctx context.Context,
		tokenHash string,
	) (int64, bool, error) {
		return 0, false, nil
	}

	next := http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		if Authenticated(r) {
			t.Fatal("expected unknown session to remain anonymous")
		}

		w.WriteHeader(http.StatusOK)
	})

	handler := Authenticate(
		config,
		lookup,
		next,
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	req.AddCookie(&http.Cookie{
		Name:  config.Session.CookieName,
		Value: "unknown-token",
	})

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			rec.Code,
		)
	}
}

func TestAuthenticateHandlesLookupErrorAsAnonymous(t *testing.T) {
	config := testConfig()

	lookup := func(
		ctx context.Context,
		tokenHash string,
	) (int64, bool, error) {
		return 0, false, errors.New("database unavailable")
	}

	next := http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		if Authenticated(r) {
			t.Fatal("expected request to remain anonymous")
		}

		w.WriteHeader(http.StatusOK)
	})

	handler := Authenticate(
		config,
		lookup,
		next,
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	req.AddCookie(&http.Cookie{
		Name:  config.Session.CookieName,
		Value: "token",
	})

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			rec.Code,
		)
	}
}

func TestRequireAuthenticationAllowsAuthenticatedRequest(t *testing.T) {
	config := testConfig()

	nextCalled := false

	next := http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := RequireAuthentication(
		config,
		next,
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/dashboard",
		nil,
	)

	ctx := context.WithValue(
		req.Context(),
		contextKey{},
		int64(42),
	)

	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusOK,
			rec.Code,
		)
	}
}

func TestRequireAuthenticationRedirectsAnonymousRequest(t *testing.T) {
	config := testConfig()

	nextCalled := false

	next := http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		nextCalled = true
	})

	handler := RequireAuthentication(
		config,
		next,
	)

	req := httptest.NewRequest(
		http.MethodGet,
		"/dashboard",
		nil,
	)

	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if nextCalled {
		t.Fatal("expected protected handler not to be called")
	}

	if rec.Code != http.StatusSeeOther {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusSeeOther,
			rec.Code,
		)
	}

	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf(
			"expected redirect to /login, got %q",
			got,
		)
	}
}

func TestUserIDReturnsFalseWithoutAuthentication(t *testing.T) {
	req := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	userID, ok := UserID(req)

	if ok {
		t.Fatal("expected no user ID")
	}

	if userID != 0 {
		t.Fatalf(
			"expected zero user ID, got %d",
			userID,
		)
	}
}
