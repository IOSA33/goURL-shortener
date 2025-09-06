package authHandler

import (
	"log"
	"net/http"
	"rest-api/internal/http-server/middleware/myJwt"
	"rest-api/templates"
	"strings"
	"time"
)

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		// returns a csrfSecret string
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{BAlertUser: csrfSecret, AlertMsg: "Hello Golang"})
	case "/login":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{false, ""})
		case "POST":
			// Parsing form data from frontend
			r.ParseForm()

			// Todo: Only logs in side projects, never logs in production
			log.Println(r.Form)

			// Todo: Change (db.FetchUserByUsername) to our database logic

			// Todo: Change our database that it return user id after adding it to database
			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			if err == nil {
				w.WriteHeader(http.StatusUnauthorized)
			}
		default:
		}
	case "/logout":
	case "/deleteUser":
	default:
	}
}

// nullifyTokenCookies sets auth token and refresh token to empty string
func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
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
	err := myJwt.RevokeRefreshToken(RefreshCookie.Value)
	if err != nil {
		return
	}
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
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

func grabCsrfFromReq(r *http.Request) string {
	csrfFromForm := r.FormValue("X-CSRF-Token")

	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}
