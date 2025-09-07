package delete

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"log/slog"
	"net/http"
	resp "rest-api/internal/lib/api/response"
)

type URLDeleter interface {
	DeleteURL(alias string) error
}

func New(log *slog.Logger, urlDeleter URLDeleter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.url.delete.New"
		log = slog.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		// Getting parameters from URL request
		alias := chi.URLParam(r, "alias")
		if alias == "" {
			log.Info("alias is empty")
			render.JSON(w, r, resp.Error("invalid request"))
			return
		}

		// if no errors it deletes URL from database with DeleteURL function
		err := urlDeleter.DeleteURL(alias)
		if err != nil {
			log.Info("url not found")
			render.JSON(w, r, resp.Error("Internal Error"))
			return
		}

		// log that is everything is correct
		log.Info("URL successfully deleted, url:", alias)
	}
}
