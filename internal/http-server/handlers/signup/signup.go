package signup

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
	"log/slog"
	"net/http"
	"rest-api/internal/domain/models"
	resp "rest-api/internal/lib/api/response"
	"rest-api/internal/lib/logger/sl"
	"rest-api/internal/storage"
)

type Request struct {
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
}

type Response struct {
	resp.Response
	Email string `json:"email,omitempty"`
}

type UserSaver interface {
	SaveUser(email string, password []byte) (uid int64, err error)
}

func New(log *slog.Logger, userSaver UserSaver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "signup.New"
		log = log.With(
			slog.String("op", op),
		)

		var user models.User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			log.Error("failed to decode request body", sl.Err(err))
			http.Error(w, "bad request decoding error", http.StatusBadRequest)
			return
		}

		log.Info("request body decoded", slog.Any("request", user.Email))

		if err := validator.New().Struct(user); err != nil {
			validateErr := err.(validator.ValidationErrors)

			log.Error("invalid request", sl.Err(err))

			http.Error(w, fmt.Sprintf("Validation error: %s", validateErr), http.StatusBadRequest)

			return
		}

		email := user.Email
		pass := user.Password
		if email == "" && len(pass) == 0 {
			validateErr := err.(validator.ValidationErrors)
			log.Error("Email required", sl.Err(err))

			http.Error(w, fmt.Sprintf("Validation error: %s", validateErr), http.StatusBadRequest)

			return
		}

		id, err := userSaver.SaveUser(email, pass)
		// This error appears when url body is empty
		if errors.Is(err, storage.ErrEmailExists) {
			log.Info("user already exists", sl.Err(err))
			render.JSON(w, r, resp.Error("user already exists"))
			return
		}
		if err != nil {
			log.Error("failed to save user", sl.Err(err))
			render.JSON(w, r, resp.Error("failed to save user"))
			return
		}

		log.Info("user added", slog.Int64("id", id))

		// Tells that everything is OK and user is added to db
		responseOK(w, r, email)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, email string) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
		Email:    email,
	})
}
