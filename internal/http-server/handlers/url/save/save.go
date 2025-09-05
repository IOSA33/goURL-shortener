package save

import (
	"errors"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"log/slog"
	"net/http"
	resp "rest-api/internal/lib/api/response"
	"rest-api/internal/lib/logger/sl"
	"rest-api/internal/lib/random"
	"rest-api/internal/storage"
)

type Request struct {
	URL   string `json:"url" validate:"required,url"`
	Alias string `json:"alias,omitempty"`
}

// TODO: move to config
const aliasLength = 6

type Response struct {
	resp.Response
	Alias string `json:"alias,omitempty"`
}

// Does not work anymore with --name flag, needs to use .mockery.yaml file
//
//go:generate go run github.com/vektra/mockery/v3@v3.5.1 --name=URLShortener
type URLSaver interface {
	SaveURL(urlToSave string, alias string) (int64, error)
}

func New(log *slog.Logger, urlSaver URLSaver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.url.save.New"
		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req Request
		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Error("failed to decode request body", sl.Err(err))
			render.JSON(w, r, resp.Error("failed to decode request"))
			return
		}
		log.Info("request body decoded", slog.Any("request", req))

		if err := validator.New().Struct(req); err != nil {
			validateErr := err.(validator.ValidationErrors)

			log.Error("invalid request", sl.Err(err))

			render.JSON(w, r, resp.ValidationError(validateErr))

			return
		}

		alias := req.Alias
		if alias == "" {
			alias = random.NewRandomString(aliasLength)
		}

		id, err := urlSaver.SaveURL(req.URL, alias)
		// This error appears when url body is empty
		if errors.Is(err, storage.ErrURLExists) {
			log.Info("url already exists", sl.Err(err))
			render.JSON(w, r, resp.Error("url already exists"))
			return
		}
		if err != nil {
			log.Error("failed to save url", sl.Err(err))
			render.JSON(w, r, resp.Error("failed to save url"))
			return
		}

		log.Info("url added", slog.Int64("id", id))

		// Tells that everything is OK and URL is added to db
		responseOK(w, r, alias)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, alias string) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
		Alias:    alias,
	})
}
