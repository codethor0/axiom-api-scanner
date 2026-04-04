package orchestrator

import (
	"context"
	"strings"
	"testing"
)

func TestService_Run_nilReceiver(t *testing.T) {
	var s *Service
	if err := s.Run(context.Background(), "550e8400-e29b-41d4-a716-446655440000", Options{}); err == nil {
		t.Fatal("want error")
	}
}

func TestService_Run_incompleteDependencies(t *testing.T) {
	s := &Service{}
	err := s.Run(context.Background(), "550e8400-e29b-41d4-a716-446655440000", Options{})
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("got %v", err)
	}
}
