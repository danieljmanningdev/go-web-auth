package password

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashCreatesBcryptHash(t *testing.T) {
	hash, err := Hash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if hash == "" {
		t.Fatal("expected password hash")
	}

	if hash == "correct-horse-battery-staple" {
		t.Fatal("expected hash to differ from plaintext password")
	}

	cost, err := Cost(hash)
	if err != nil {
		t.Fatalf("read bcrypt cost: %v", err)
	}

	if cost != bcrypt.DefaultCost {
		t.Fatalf(
			"expected bcrypt cost %d, got %d",
			bcrypt.DefaultCost,
			cost,
		)
	}
}

func TestCompareAcceptsCorrectPassword(t *testing.T) {
	hash, err := Hash("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if !Compare(hash, "correct-password") {
		t.Fatal("expected correct password to match")
	}
}

func TestCompareRejectsIncorrectPassword(t *testing.T) {
	hash, err := Hash("correct-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if Compare(hash, "wrong-password") {
		t.Fatal("expected incorrect password not to match")
	}
}

func TestHashUsesUniqueSalt(t *testing.T) {
	first, err := Hash("same-password")
	if err != nil {
		t.Fatalf("hash first password: %v", err)
	}

	second, err := Hash("same-password")
	if err != nil {
		t.Fatalf("hash second password: %v", err)
	}

	if first == second {
		t.Fatal("expected identical passwords to produce different hashes")
	}

	if !Compare(first, "same-password") {
		t.Fatal("expected first hash to verify")
	}

	if !Compare(second, "same-password") {
		t.Fatal("expected second hash to verify")
	}
}

func TestHashRejectsPasswordLongerThanBcryptLimit(t *testing.T) {
	plain := strings.Repeat("a", 73)

	_, err := Hash(plain)

	if !errors.Is(err, ErrTooLong) {
		t.Fatalf(
			"expected ErrTooLong, got %v",
			err,
		)
	}
}

func TestCompareRejectsInvalidHash(t *testing.T) {
	if Compare("not-a-valid-bcrypt-hash", "password") {
		t.Fatal("expected invalid hash not to match")
	}
}
