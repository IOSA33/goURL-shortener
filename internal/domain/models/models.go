package models

import (
	"github.com/golang-jwt/jwt"
	"rest-api/internal/lib/random"
	"time"
)

type User struct {
	ID       int64
	Email    string
	Password []byte
	Role     string
}

type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const RefreshTokenValidTime = time.Hour * 72
const AuthTokenValidTime = time.Minute * 15

func GenerateCSRFSecret() (string, error) {
	return random.NewRandomString(32), nil
}
