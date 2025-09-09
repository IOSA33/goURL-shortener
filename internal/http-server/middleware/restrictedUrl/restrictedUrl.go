package restrictedUrl

import (
	"log/slog"
	"net/http"
	"rest-api/internal/lib/logger/sl"
	"rest-api/internal/lib/myJwt"
)

// TODO: Middleware for only authenticated users
func New(log *slog.Logger, jwtService myJwt.JwtService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			const op = "middleware.restrictedUrl.New"
			log = log.With(
				slog.String("op", op),
			)

			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Error("Unauthorized attempt! No auth Cookie", slog.String("error", authErr.Error()))
				myJwt.NullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusUnauthorized), 401)
				return
			} else if authErr != nil {
				log.Error("Unauthorized attempt! Internal Server Error", slog.String("error", authErr.Error()))
				myJwt.NullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusInternalServerError), 500)
				return
			}

			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Error("Unauthorized attempt! No refresh Cookie", slog.String("error", authErr.Error()))
				myJwt.NullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			} else if refreshErr != nil {
				log.Error("Unauthorized attempt! Internal Server Error", slog.String("error", authErr.Error()))
				myJwt.NullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(http.StatusInternalServerError), 500)
				return
			}

			requestCsrfToken := myJwt.GrabCsrfFromReq(r)
			log.Info(requestCsrfToken)

			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err == "Unauthorized" {
					log.Error("Unauthorized attempt! JWT's not valid")
					http.Error(w, http.StatusText(http.StatusUnauthorized), 401)
					return
				} else {
					log.Error("Error is not nil", slog.String("error", authErr.Error()))
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}

			log.Info("Successfully recreated jwts")

			// Change value to only correct sites
			w.Header().Set("Access-Control-Allow-Origin", "*")
			myJwt.SetAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
