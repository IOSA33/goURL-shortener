package register

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"log/slog"
	"net/http"
	resp "rest-api/internal/lib/api/response"
	"rest-api/internal/lib/logger/sl"
	"rest-api/internal/lib/myJwt"
	"rest-api/internal/storage"
	"time"
)

var (
	roleUser                   = "user"
	ContextTimeOutForUserSaver = 3 * time.Second
)

type Request struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password,omitempty" validate:"required,min=6"`
}

type Response struct {
	resp.Response
	Email string `json:"email,omitempty"`
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, password []byte) (uid int64, err error)
}

func New(log *slog.Logger, userSaver UserSaver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "register.New"
		log = log.With(
			slog.String("op", op),
		)

		if err := r.ParseForm(); err != nil {
			log.Error("failed to parse form", slog.String("error", err.Error()))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), ContextTimeOutForUserSaver)
		defer cancel()

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

			http.Error(w, fmt.Sprintf("Validation error: %s", validateErr), http.StatusBadRequest)

			return
		}

		id, err := userSaver.SaveUser(ctx, req.Email, []byte(req.Password))
		// This error appears when url body is empty
		if errors.Is(err, storage.ErrEmailExists) {
			log.Info("email already exists", sl.Err(err))
			render.JSON(w, r, resp.Error("email already exists"))
			return
		}
		if err != nil {
			log.Error("failed to save user", sl.Err(err))
			render.JSON(w, r, resp.Error("failed to save user"))
			return
		}

		log.Info("user added", slog.Int64("id", id))

		// Adding JWT token for user
		authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(req.Email, roleUser)
		if err != nil {
			log.Error("failed to get Auth tokens", sl.Err(err))
			render.JSON(w, r, resp.Error("failed to get Auth tokens"))
			return
		}

		myJwt.SetAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
		w.Header().Set("X-CSRF-Token", csrfSecret)
		// Tells that everything is OK and user is added to db
		responseOK(w, r, req.Email)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, email string) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
		Email:    email,
	})
}
