package main

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log/slog"
	"net/http"
	"os"

	ssogrpc "rest-api/internal/clients/sso/grpc"

	"rest-api/internal/config"
	"rest-api/internal/http-server/handlers/redirect"
	"rest-api/internal/http-server/handlers/url/deleteUrl"
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

	// Adding Auth (sso) service
	// Now this service can be implemented in middlewares or something
	ssoClient, err := ssogrpc.New(
		context.Background(),
		log,
		cfg.Clients.SSO.Address,
		cfg.Clients.SSO.Timeout,
		cfg.Clients.SSO.RetriesCount,
	)
	if err != nil {
		log.Error("failed to init sso client", sl.Err(err))
		os.Exit(1)
	}

	ssoClient.IsAdmin(context.Background(), 1)

	// init storage: SQLite
	storage, err := sqlite.New(cfg.StoragePath)
	if err != nil {
		log.Error("Error to init storage", sl.Err(err))
		os.Exit(1)
	}
	_ = storage

	// init router: chi, "chi render"
	router := chi.NewRouter()

	// middleware
	router.Use(middleware.RequestID)
	router.Use(middleware.Logger)
	router.Use(mwLogger.New(log))
	router.Use(middleware.Recoverer)
	router.Use(middleware.URLFormat)

	// basic auth with chi
	router.Route("/url", func(r chi.Router) {
		r.Use(middleware.BasicAuth("url-shortener", map[string]string{
			cfg.HTTPServer.User: cfg.HTTPServer.Password,
		}))

		// post method to save url
		r.Post("/", save.New(log, storage))
		r.Delete("/delete/{alias}", deleteUrl.New(log, storage))
	})

	// get method that redirects user to found url
	router.Get("/{alias}", redirect.New(log, storage))

	// TODO: GET without chi

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
