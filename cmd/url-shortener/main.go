package main

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log/slog"
	"net/http"
	"os"
	"rest-api/internal/http-server/handlers/authHandlers/register"
	"rest-api/internal/http-server/middleware/restrictedUrl"
	"rest-api/internal/lib/myJwt"
	"rest-api/templates"

	"rest-api/internal/config"
	"rest-api/internal/http-server/handlers/redirect"
	"rest-api/internal/http-server/handlers/url/delete"
	"rest-api/internal/http-server/handlers/url/save"
	mwLogger "rest-api/internal/http-server/middleware/logger" // custom name of import
	"rest-api/internal/lib/logger/handlers/slogpretty"
	"rest-api/internal/lib/logger/sl"
	eventsender "rest-api/internal/services/event_sender"
	"rest-api/internal/storage/sqlite"
	"time"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	// init config: cleanenv
	cfg := config.MustLoad()

	// init logger: sl
	log := setupLogger(cfg.Env)
	log.Info("Starting URL-Shortener ", slog.String("env", cfg.Env))
	log.Debug("debug messages are enabled")

	jwtService := myJwt.NewJWTService(log)

	// init storage: SQLite
	storage, err := sqlite.New(cfg.StoragePath)
	if err != nil {
		log.Error("Error to init storage", sl.Err(err))
		os.Exit(1)
	}
	_ = storage

	// init router: chi, "chi render"
	router := chi.NewRouter()

	// TODO: From here needs to move to internal/app
	// middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(mwLogger.New(log))
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	// Registration and Login
	router.Get("/register", func(w http.ResponseWriter, r *http.Request) {
		templates.RenderTemplate(w, "register", &templates.RegisterPage{false, ""})
	})
	router.Post("/register", register.New(log, storage))

	// When user is logging out
	router.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		myJwt.NullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", http.StatusFound)
	})

	// Todo: middleware for restrictedUrl url paths
	router.Route("/url", func(r chi.Router) {
		// TODO: make restricted logic
		r.Use(restrictedUrl.New(log))

		// post method to save url
		r.Post("/", save.New(log, storage))
		r.Delete("/delete/{alias}", delete.New(log, storage))
	})

	// get method that redirects user to found url
	router.Get("/{alias}", redirect.New(log, storage))

	// TODO: To here

	log.Info("starting server", slog.String("address", cfg.Address))
	// server config
	srv := &http.Server{
		Addr:         cfg.Address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	sender := eventsender.New(storage, log)
	// TODO: second parameter is better to move to config file
	sender.StartProcessEvents(context.Background(), 60*time.Second)

	// run server:
	if err := srv.ListenAndServe(); err != nil {
		log.Error("Failed to start server")
	}

	log.Error("server stopped")
}

// TODO: This also
func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	// different cases, if server is Local, Developer or Production
	switch env {
	case envLocal:
		log = setupPrettySlog()
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	default:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	return log
}

// function only for local use, for Pretty Logs in console
func setupPrettySlog() *slog.Logger {
	opts := slogpretty.PrettyHandlerOptions{
		SlogOpts: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}

	handler := opts.NewPrettyHandler(os.Stdout)

	return slog.New(handler)
}
