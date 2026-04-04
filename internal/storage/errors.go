package storage

import "errors"

var (
	// ErrNotFound means the requested row does not exist.
	ErrNotFound = errors.New("storage: not found")
	// ErrInvalidTransition means the scan cannot accept the requested control action.
	ErrInvalidTransition = errors.New("storage: invalid scan status transition")
	// ErrDuplicateFinding means a finding with the same evidence tuple already exists.
	ErrDuplicateFinding = errors.New("storage: duplicate finding for evidence tuple")
)
