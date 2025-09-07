package restrictedUrl

import (
	"log/slog"
	"net/http"
	"rest-api/internal/lib/myJwt"
)

// TODO: Middleware for only authenticated users
func New(log *slog.Logger, jwtService myJwt.JwtService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}
