package myJwt

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt"
	"os"
	"rest-api/internal/domain/models"
	"time"
)

const (
	privKeyPath = "./lib/keys/app.rsa"
	pubKeyPath  = "./lib/keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func InitJWT() error {
	// Reading private key from a file
	signBytes, err := os.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	// Parsing it to readable format for program
	// Doing equal to variable in var
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	// Same with publicKey
	verifyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil

}

// CreateNewTokens creates a tokens with JWT token, csrf secret and refresh token
func CreateNewTokens(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {
	// generate the csrf secret
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	// generating the refresh token
	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)

	// generation the auth token
	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}
	return
}

func CheckAndRefreshTokens() {

}

func createAuthTokenString(uuid string, role string, csrfSecret string) (authTokenString string, err error) {
	// When token will expire
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	// Defying what token will contain
	authClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  "",
			ExpiresAt: authTokenExp,
			Id:        "",
			IssuedAt:  0,
			Issuer:    "",
			NotBefore: 0,
			Subject:   uuid,
		},
		Role: role,
		Csrf: csrfSecret,
	}

	// NewWithClaims transforms out authClaims struct into hashed format
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	// After that we are signing the hashed jwt token with our RSA secret key
	authTokenString, err = authJwt.SignedString(signKey)
	return
}

func createRefreshTokenString(uuid string, role string, csrfString string) (refreshTokenString string, err error) {
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	// Todo: database for Tokens
	refreshJti, err := db.StoreRefreshToken()
	if err != nil {
		return
	}

	// ID: refreshJti in standardClaims is the id for the token itself,
	// for example when we want to revoke this token.
	refreshClaims := models.TokenClaims{
		StandardClaims: jwt.StandardClaims{
			Audience:  "",
			ExpiresAt: refreshTokenExp,
			Id:        refreshJti,
			IssuedAt:  0,
			Issuer:    "",
			NotBefore: 0,
			Subject:   uuid,
		},
		Role: role,
		Csrf: csrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func updateRefreshTokenExp() {

}

func updateAuthTokenString() {

}

func RevokeRefreshToken() error {

}

func updateRefreshTokenCsrf() {

}

func GrabUUID() {

}
