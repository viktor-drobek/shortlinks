package worker

import (
	"context"
	"github.com/viktor-drobek/shortlinks/internal/store"
	"log/slog"
	"time"
)

type Check func(context.Context, string) string
type Worker struct {
	Store *store.Store
	Check Check
	Batch int
	Poll  time.Duration
}

func (w Worker) Run(ctx context.Context) {
	if w.Batch <= 0 {
		w.Batch = 32
	}
	if w.Poll <= 0 {
		w.Poll = time.Minute
	}
	tick := time.NewTicker(w.Poll)
	defer tick.Stop()
	for {
		if err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("destination checker pass failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
func (w Worker) RunOnce(ctx context.Context) error {
	if w.Batch <= 0 || w.Batch > 32 {
		w.Batch = 32
	}
	links, e := w.Store.Due(ctx, w.Batch, 10*time.Minute)
	if e != nil {
		return e
	}
	for _, l := range links {
		v := "uncertain"
		if w.Check != nil {
			bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
			v = w.Check(bounded, l.URL)
			cancel()
		}
		if v != "healthy" && v != "missing" {
			v = "uncertain"
		}
		if e = w.Store.Complete(ctx, l, v); e != nil {
			return e
		}
	}
	return nil
}
