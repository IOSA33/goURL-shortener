package myJwt

import (
	"crypto/rsa"
	"errors"
	"github.com/golang-jwt/jwt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"rest-api/internal/domain/models"
	"time"
)

type JWTService struct {
	log *slog.Logger
}

const (
	privKeyPath = "./lib/keys/app.rsa"
	pubKeyPath  = "./lib/keys/app.rsa.pub"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

func NewJWTService(log *slog.Logger) *JWTService {
	return &JWTService{log: log}
}

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

// CheckAndRefreshTokens checks old JWT token from user request and if it is okay, returns new token
func (j *JWTService) CheckAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {

	if oldCsrfSecret == "" {
		log.Println("No CSRF token!")
		err = errors.New("Unauthorized")
		return
	}

	jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifykey, nil
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	if oldCsrfSecret != authTokenClaims.Csrf {
		j.log.Info("CSRF token doesn't match jwt!")
		err = errors.New("Unauthorized")
		return
	}

	if authToken.Valid {
		j.log.Info("AuthToken is valid")
	}
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

// NullifyTokenCookies sets auth token and refresh token to empty string
func NullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	// if present, revoke the refresh cookie from our db
	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		// Do nothing, there is no refresh cookie present
		return
	} else if refreshErr != nil {
		log.Panic("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	}
	// RevokeRefreshToken is function that deletes token from db, that user cannot use it later
	err := RevokeRefreshToken(RefreshCookie.Value)
	if err != nil {
		return
	}
}

func SetAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshTokenString,
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)
}

func GrabCsrfFromReq(r *http.Request) string {
	csrfFromForm := r.FormValue("X-CSRF-Token")

	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}
