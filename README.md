# go-web-auth

[![CI](https://github.com/danieljmanningdev/go-web-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/danieljmanningdev/go-web-auth/actions/workflows/ci.yml)

Reusable authentication primitives for Go web applications.

`go-web-auth` provides small, focused packages for password hashing, secure session handling, and request authentication middleware.

It is designed to work alongside:

* [`go-web-core`](https://github.com/danieljmanningdev/go-web-core)
* [`go-web-security`](https://github.com/danieljmanningdev/go-web-security)

but does not depend on either of them.

The package deliberately avoids application-specific user models, database schemas, registration flows, roles, permissions, password resets, and business logic.

## Features

* Password hashing with bcrypt
* Password verification
* Bcrypt cost inspection
* Secure random session-token generation
* SHA-256 session-token hashing for storage
* Secure session-cookie helpers
* Session-cookie removal
* Database-agnostic session lookup
* Authentication middleware
* Authenticated user IDs stored in request context
* Protected-route middleware
* Automated tests for core authentication behaviour

## Installation

```bash
go get github.com/danieljmanningdev/go-web-auth@v0.1.0
```

## Packages

### `password`

Provides password hashing and verification using `golang.org/x/crypto/bcrypt`.

Hash a password:

```go
hash, err := password.Hash("correct-horse-battery-staple")
if err != nil {
	log.Fatal(err)
}
```

Verify a password:

```go
if !password.Compare(hash, suppliedPassword) {
	// Invalid password.
}
```

Read the bcrypt cost of an existing hash:

```go
cost, err := password.Cost(hash)
if err != nil {
	log.Fatal(err)
}
```

Passwords longer than bcrypt's supported maximum are rejected with:

```go
password.ErrTooLong
```

Example:

```go
hash, err := password.Hash(plainPassword)
if err != nil {
	if errors.Is(err, password.ErrTooLong) {
		// Handle password length error.
	}

	return err
}
```

---

### `session`

Provides secure session-token generation, hashing, and cookie helpers.

#### Generate a session token

```go
token, err := session.GenerateToken()
if err != nil {
	log.Fatal(err)
}
```

Session tokens are generated using cryptographically secure randomness.

#### Hash a token for storage

```go
tokenHash := session.HashToken(token)
```

A recommended pattern is:

```text
Browser cookie:
raw session token

Database:
SHA-256 hash of session token
```

This means the raw bearer token does not need to be stored in the database.

#### Default configuration

```go
config := session.DefaultConfig()
```

Defaults include:

```text
Cookie name: session
Path: /
Secure: true
HttpOnly: true
SameSite: Lax
Maximum age: 24 hours
```

For local development over plain HTTP:

```go
config := session.DefaultConfig()
config.Secure = false
```

Production applications should normally keep secure cookies enabled.

#### Set a session cookie

```go
session.SetCookie(
	w,
	config,
	token,
)
```

#### Read the current session token

```go
token, err := session.TokenFromRequest(
	r,
	config,
)

if errors.Is(err, session.ErrNoSession) {
	// Anonymous request.
}
```

#### Clear a session cookie

```go
session.ClearCookie(
	w,
	config,
)
```

---

### `middleware`

Provides authentication and protected-route middleware.

The package is database-agnostic.

Your application supplies a session lookup function:

```go
func lookupSession(
	ctx context.Context,
	tokenHash string,
) (int64, bool, error) {
	// Look up the hashed token in your database.

	// Return:
	// user ID
	// whether the session exists
	// any lookup error
}
```

#### Authenticate requests

```go
handler := middleware.Authenticate(
	middleware.Config{
		Session:  sessionConfig,
		LoginURL: "/login",
	},
	lookupSession,
	mux,
)
```

When a valid session exists, the authenticated user ID is attached to the request context.

Anonymous requests are allowed to continue without an authenticated identity.

#### Read the authenticated user ID

```go
userID, ok := middleware.UserID(r)

if !ok {
	// Anonymous request.
}
```

You can also check authentication directly:

```go
if middleware.Authenticated(r) {
	// Authenticated request.
}
```

#### Protect a route

```go
protected := middleware.RequireAuthentication(
	middleware.Config{
		Session:  sessionConfig,
		LoginURL: "/login",
	},
	dashboardHandler,
)
```

Anonymous requests are redirected to the configured login URL.

## Example

A simplified application might look like:

```go
package main

import (
	"context"
	"log"
	"net/http"

	authmiddleware "github.com/danieljmanningdev/go-web-auth/middleware"
	"github.com/danieljmanningdev/go-web-auth/session"
)

func main() {
	sessionConfig := session.DefaultConfig()

	lookupSession := func(
		ctx context.Context,
		tokenHash string,
	) (int64, bool, error) {
		// Replace this with a database lookup.

		return 0, false, nil
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		_, _ = w.Write([]byte("public"))
	})

	dashboard := http.HandlerFunc(func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		userID, ok := authmiddleware.UserID(r)
		if !ok {
			http.Error(
				w,
				"authentication required",
				http.StatusUnauthorized,
			)
			return
		}

		_ = userID

		_, _ = w.Write([]byte("dashboard"))
	})

	protectedDashboard := authmiddleware.RequireAuthentication(
		authmiddleware.Config{
			Session:  sessionConfig,
			LoginURL: "/login",
		},
		dashboard,
	)

	mux.Handle(
		"/dashboard",
		protectedDashboard,
	)

	handler := authmiddleware.Authenticate(
		authmiddleware.Config{
			Session:  sessionConfig,
			LoginURL: "/login",
		},
		lookupSession,
		mux,
	)

	if err := http.ListenAndServe(
		":8080",
		handler,
	); err != nil {
		log.Fatal(err)
	}
}
```

## Creating a login session

A typical login flow is:

```go
token, err := session.GenerateToken()
if err != nil {
	return err
}

tokenHash := session.HashToken(token)
```

Store `tokenHash` in your application's session table alongside information such as:

```text
user_id
token_hash
expires_at
created_at
```

Then send the raw token to the browser:

```go
session.SetCookie(
	w,
	sessionConfig,
	token,
)
```

Later requests send the raw token back through the cookie.

Your application's lookup function hashes that token and compares the resulting value against the stored session.

## Logging out

A typical logout flow should:

1. Read the session token from the request.
2. Hash the token.
3. Remove or invalidate the matching database session.
4. Clear the browser cookie.

For example:

```go
token, err := session.TokenFromRequest(
	r,
	sessionConfig,
)
if err == nil {
	tokenHash := session.HashToken(token)

	_ = tokenHash

	// Delete tokenHash from the application's session store.
}

session.ClearCookie(
	w,
	sessionConfig,
)
```

## Database independence

`go-web-auth` does not provide a session database or user repository.

That is intentional.

Applications can use:

* SQLite
* PostgreSQL
* MySQL
* another persistent store

without changing the authentication primitives.

The application remains responsible for:

* creating its user table
* creating its session table
* looking up sessions
* expiring sessions
* deleting sessions
* loading complete user records
* authorization and permissions

## Design philosophy

This project provides **authentication primitives rather than a complete identity framework**.

It handles reusable mechanics such as:

```text
password hashing
session token generation
session cookie handling
request authentication
protected routes
```

Application-specific concerns remain outside this package.

That includes:

```text
registration
user profiles
email verification
password reset
roles
permissions
OAuth
MFA
account suspension
business-specific authorization
```

The goal is simple:

> Give new Go web applications a small, tested authentication foundation without forcing a particular database or user model.

## Development

Format the code:

```bash
gofmt -w .
```

Run the tests:

```bash
go test ./...
```

Run static analysis:

```bash
go vet ./...
```

Check whitespace errors:

```bash
git diff --check
```

## Status

The project is currently in early development.

Until the API stabilises, releases should be considered pre-`v1.0.0` and may contain breaking changes.

Current release:

```text
v0.1.0
```

## License

See [LICENSE](LICENSE).
