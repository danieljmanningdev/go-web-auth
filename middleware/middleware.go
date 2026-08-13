package middleware

import (
	"context"
	"net/http"

	"github.com/danieljmanningdev/go-web-auth/session"
)

type contextKey struct{}

type SessionLookup func(
	ctx context.Context,
	tokenHash string,
) (int64, bool, error)

type Config struct {
	Session  session.Config
	LoginURL string
}

func Authenticate(
	config Config,
	lookup SessionLookup,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		token, err := session.TokenFromRequest(
			r,
			config.Session,
		)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		tokenHash := session.HashToken(token)

		userID, found, err := lookup(
			r.Context(),
			tokenHash,
		)
		if err != nil || !found {
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(
			r.Context(),
			contextKey{},
			userID,
		)

		next.ServeHTTP(
			w,
			r.WithContext(ctx),
		)
	})
}

func RequireAuthentication(
	config Config,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		if !Authenticated(r) {
			http.Redirect(
				w,
				r,
				config.LoginURL,
				http.StatusSeeOther,
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func UserID(r *http.Request) (int64, bool) {
	userID, ok := r.Context().Value(
		contextKey{},
	).(int64)

	return userID, ok
}

func Authenticated(r *http.Request) bool {
	_, ok := UserID(r)
	return ok
}
