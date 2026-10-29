package main

import (
	"context"
	"github.com/viktor-drobek/shortlinks/internal/checker"
	"github.com/viktor-drobek/shortlinks/internal/config"
	"github.com/viktor-drobek/shortlinks/internal/server"
	"github.com/viktor-drobek/shortlinks/internal/store"
	"github.com/viktor-drobek/shortlinks/internal/worker"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	syscall.Umask(0o077)
	db := env("SHORTLINKS_DB", "/var/lib/shortlinks/links.db")
	if e := config.EnsurePrivateDBDir(db); e != nil {
		slog.Error("create data directory", "error", e)
		os.Exit(1)
	}
	key, e := config.ReadKey(env("SHORTLINKS_KEY_FILE", "/run/secrets/shortlinks_key"))
	if e != nil {
		slog.Error("read encryption key", "error", e)
		os.Exit(1)
	}
	proxy, e := config.ReadPrivate(env("SHORTLINKS_PROXY_KEY_FILE", "/run/secrets/shortlinks_proxy_key"))
	if e != nil {
		slog.Error("read proxy key", "error", e)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	st, e := store.Open(ctx, db, key)
	if e != nil {
		slog.Error("open store", "error", e)
		os.Exit(1)
	}
	defer st.Close()
	if e := os.Chmod(db, 0600); e != nil {
		slog.Error("database permissions failed")
		os.Exit(1)
	}
	go func() {
		w := worker.Worker{Store: st, Check: func(ctx context.Context, target string) string { return string(checker.Check(ctx, target).Verdict) }}
		if err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Error("initial checker pass failed")
		}
		w.Run(ctx)
	}()
	srv := &http.Server{Addr: env("SHORTLINKS_LISTEN", ":8080"), Handler: server.New(server.Config{Store: st, ProxyKey: proxy, BaseURL: env("SHORTLINKS_BASE_URL", "https://s.2050.su"), Origin: env("SHORTLINKS_ORIGIN", "https://s.2050.su")}).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	slog.Info("shortlinks listening", "address", srv.Addr)
	if e = srv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
		slog.Error("server stopped", "error", e)
		os.Exit(1)
	}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
