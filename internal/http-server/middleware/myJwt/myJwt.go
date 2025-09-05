package myJwt

import (
	"crypto/rsa"
	"github.com/golang-jwt/jwt"
	"os"
	"rest-api/internal/domain/models"
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

func CreateNewTokens(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {
	// generate the csrf secret
	csrfSecret, err := models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	// generating the refresh token
	createRefreshTokenString(uuid, role, csrfSecret)

	// geneeration the auth token
}

func CheckAndRefreshTokens() {

}

func createAuthTokenString() {

}

func createRefreshTokenString() {

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
