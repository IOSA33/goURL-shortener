package myJwt

import (
	"crypto/rsa"
	"errors"
	"fmt"
	jwt "github.com/golang-jwt/jwt"
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

// CheckAndRefreshTokens checks old JWT token from user request and if it is okay, returns refreshed token
func (j *JWTService) CheckAndRefreshTokens(oldAuthTokenString string, oldRefreshTokenString string, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string, err error) {

	if oldCsrfSecret == "" {
		log.Println("No CSRF token!")
		err = errors.New("unauthorized")
		return
	}

	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	if oldCsrfSecret != authTokenClaims.Csrf {
		j.log.Info("CSRF token doesn't match jwt!")
		err = errors.New("unauthorized")
		return
	}

	if authToken.Valid {
		log.Println("Auth token is valid")

		newCsrfSecret = authTokenClaims.Csrf

		newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
		newAuthTokenString = oldAuthTokenString
		return
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		log.Println("Auth token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			log.Println("Auth token is expired")

			newAuthTokenString, newCsrfSecret, err = updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)
			if err != nil {
				return
			}

			newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)
			if err != nil {
				return
			}

			newRefreshTokenString, err = updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
			return
		} else {
			log.Println("Error in auth token")
			err = errors.New("Error in auth token")
			return
		}
	} else {
		log.Println("Error in auth token")
		err = errors.New("Error in auth token")
		return
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

func updateRefreshTokenExp(oldRefreshTokenString string) (newRefreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return
	}

	// Giving same new time
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()

	// So we parse old token and gives it to the refresh token, same values as the old one
	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        oldRefreshTokenClaims.StandardClaims.Id,
			Subject:   oldRefreshTokenClaims.StandardClaims.Subject,
			ExpiresAt: refreshTokenExp,
		},
		oldRefreshTokenClaims.Role,
		oldRefreshTokenClaims.Csrf,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func (j *JWTService) updateAuthTokenString(refreshTokenString string, oldAuthTokenString string) (newAuthTokenString, csrfSecret string, err error) {
	// Same thing again and again, so we're getting token and parsing it
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		err = fmt.Errorf("error reading jwt claims")
		j.log.Error(err.Error())
		return
	}

	// TODO: Change to our database
	if db.CheckRefreshToken(refreshTokenClaims.StandardClaims.Id) {

		if refreshToken.Valid {

			authToken, _ := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
				return verifyKey, nil
			})

			oldAuthTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
			if !ok {
				err = fmt.Errorf("error reading jwt claims")
				j.log.Error(err.Error())
				return
			}

			csrfSecret, err = models.GenerateCSRFSecret()
			if err != nil {
				return
			}

			// Subject is the uuid of the user
			newAuthTokenString, err = createAuthTokenString(oldAuthTokenClaims.StandardClaims.Subject, oldAuthTokenClaims.Role, csrfSecret)

			return
		} else {
			j.log.Info("Refresh token has expired!")

			// TODO: change to our database
			db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

			err = errors.New("unauthorized")
			return
		}
	} else {
		j.log.Info("Refresh token has been revoked!")

		err = errors.New("unauthorized")
		return
	}
}

func RevokeRefreshToken(refreshTokenString string) error {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		return errors.New("Could not parse refresh token with claims")
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)
	if !ok {
		return errors.New("Could not read refresh token claims")
	}

	// TODO: change db
	db.DeleteRefreshToken(refreshTokenClaims.StandardClaims.Id)

	return nil
}

func updateRefreshTokenCsrf() {

}

// GrabUUID returns users uid, first it claims usersToken and from there it returns users subject uuid
func GrabUUID(authTokenString string) (string, error) {
	authToken, _ := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return "", errors.New("Error fetching claims")
	})

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok {
		return "", errors.New("error fetching claims")
	}

	return authTokenClaims.StandardClaims.Subject, nil
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
