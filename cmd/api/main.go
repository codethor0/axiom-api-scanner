package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chomechomekitchen/axiom-api-scanner/internal/api"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/dbmigrate"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/executor/baseline"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/executor/mutation"
	"github.com/chomechomekitchen/axiom-api-scanner/internal/storage/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	slog.SetDefault(log)

	rulesDir := os.Getenv("AXIOM_RULES_DIR")
	if rulesDir == "" {
		rulesDir = "rules"
	}

	addr := os.Getenv("AXIOM_HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Error("DATABASE_URL is required for the control plane")
		os.Exit(1)
	}

	migrationsDir := os.Getenv("AXIOM_MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations"
	}
	if err := dbmigrate.Up(dsn, migrationsDir); err != nil {
		log.Error("database migrations failed", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Error("database pool", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	store := postgres.NewStore(pool)
	h := &api.Handler{
		RulesDir:    rulesDir,
		Scans:       store,
		ScanTargets: store,
		Endpoints:   store,
		Executions:  store,
		Findings:    store,
		Evidence:    store,
		Baseline:    baseline.NewRunner(store),
		Mutations:   mutation.NewRunner(store),
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           h.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Info("api listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown", "err", err)
	}
}
