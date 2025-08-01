package slogdiscard

import (
	"context"
	"log/slog"
)

// slogdiscard is a method for tests that does not write logs in console

func NewDiscardLogger() *slog.Logger {
	return slog.New(NewDiscardHandler())
}

type DiscardHandler struct{}

func NewDiscardHandler() *DiscardHandler {
	return &DiscardHandler{}
}

func (h *DiscardHandler) Handle(_ context.Context, _ slog.Record) error {
	// ignore list
	return nil
}

func (h *DiscardHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	// return empty list
	return h
}

func (h *DiscardHandler) WithGroup(_ string) slog.Handler {
	// returns empty list
	return h
}

func (h *DiscardHandler) Enabled(_ context.Context, _ slog.Level) bool {
	// always returns false, because no items to save in log
	return false
}
