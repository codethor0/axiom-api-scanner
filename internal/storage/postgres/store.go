package postgres

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store implements scan, finding, and evidence metadata repositories against PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store that uses the given pool. The pool lifecycle is owned by the caller.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}
