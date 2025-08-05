package eventsender

import (
	"context"
	"log/slog"
	"rest-api/internal/domain"
	"rest-api/internal/lib/logger/sl"
	"rest-api/internal/storage/sqlite"
	"time"
)

type Sender struct {
	storage *sqlite.Storage
	log     *slog.Logger
}

func New(storage *sqlite.Storage, log *slog.Logger) *Sender {
	return &Sender{
		storage: storage,
		log:     log,
	}
}

func (s *Sender) StartProcessEvents(ctx context.Context, handlePeriod time.Duration) {
	const op = "services.event-sender.StartProcessEvents"

	log := s.log.With(slog.String("op", op))

	ticker := time.NewTicker(handlePeriod)

	go func() {
		for {
			select {
			case <-ctx.Done():
				log.Info("stopping event processing")
				return
			case <-ticker.C:
				// noop
			}

			event, err := s.storage.GetNewEvent()
			if err != nil {
				log.Error("failed to get new event", sl.Err(err))
				continue
			}
			if event.ID == 0 {
				log.Debug("no new events")
				continue
			}

			s.SendMessage(event)

			if err := s.storage.SetDone(event.ID); err != nil {
				log.Error("failed to set event done", sl.Err(err))
			}
		}
	}()
}

func (s *Sender) SendMessage(event domain.Event) {
	const op = "services.event-sender.SendMessage"
	log := s.log.With(slog.String("op", op))
	log.Info("sending message", slog.Any("event", event))
	// TODO: implement sending message to the external service.
}
