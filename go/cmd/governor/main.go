package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gnanirahulnutakki/ardur/go/pkg/governance"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := governance.LoadFromEnv()
	if err := cfg.Validate(); err != nil {
		logger.Error("invalid configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	store := governance.NewMemoryStore()
	engine := governance.NewEngine()
	sink := governance.NewLoggingActionSink()

	service := governance.NewSessionService(store, engine, sink)
	// FIX-R5-H2 (2026-04-29): construct the auth-aware handler when a
	// token is configured. Validate() refuses to start unless either
	// (a) RequireAuth is true AND a 32+ byte token is supplied, or
	// (b) RequireAuth is false (explicit dev-mode opt-out via env).
	var handler *governance.Handler
	if cfg.RequireAuth {
		handler = governance.NewHandlerWithAuth(service, cfg.AuthToken)
	} else {
		logger.Warn(
			"bearer-token auth DISABLED via ARDUR_GOVERNOR_NO_REQUIRE_AUTH; " +
				"every /v1/* endpoint accepts unauthenticated requests. " +
				"Use only for local development.")
		handler = governance.NewHandler(service)
	}

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      handler.Routes(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting governor", slog.String("addr", cfg.ListenAddr))
		errCh <- srv.ListenAndServe()
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", slog.String("error", err.Error()))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("shutdown error", slog.String("error", err.Error()))
		os.Exit(1)
	}

	store.Close()
	logger.Info("governor stopped")
}
