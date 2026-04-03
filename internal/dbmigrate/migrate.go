package dbmigrate

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// Up applies all pending migrations from migrationsDir (absolute URL built internally).
func Up(databaseURL, migrationsDir string) error {
	abs, err := filepath.Abs(migrationsDir)
	if err != nil {
		return fmt.Errorf("migrations path: %w", err)
	}
	src := fmt.Sprintf("file://%s", filepath.ToSlash(abs))
	m, err := migrate.New(src, databaseURL)
	if err != nil {
		return fmt.Errorf("migrate new: %w", err)
	}
	defer func() {
		_, _ = m.Close() // source and database close errors ignored after Up
	}()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}
