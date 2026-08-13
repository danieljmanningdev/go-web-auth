package password

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var ErrTooLong = errors.New("password exceeds bcrypt maximum length")

func Hash(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(plain),
		bcrypt.DefaultCost,
	)
	if err != nil {
		if errors.Is(err, bcrypt.ErrPasswordTooLong) {
			return "", ErrTooLong
		}

		return "", err
	}

	return string(hash), nil
}

func Compare(hash, plain string) bool {
	err := bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(plain),
	)

	return err == nil
}

func Cost(hash string) (int, error) {
	return bcrypt.Cost([]byte(hash))
}
