package aat

import (
	"errors"
	"testing"
)

func assertInvariantPlaceholder(t *testing.T, err error, invariant string) {
	t.Helper()
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("%s placeholder should wrap ErrNotImplemented, got %v", invariant, err)
	}
}

func TestInvariantI1Placeholder(t *testing.T) {
	assertInvariantPlaceholder(t, ErrInvariantI1NotImplemented, "I1")
}

func TestInvariantI2Placeholder(t *testing.T) {
	assertInvariantPlaceholder(t, ErrInvariantI2NotImplemented, "I2")
}

func TestInvariantI3Placeholder(t *testing.T) {
	assertInvariantPlaceholder(t, ErrInvariantI3NotImplemented, "I3")
}

func TestInvariantI4Placeholder(t *testing.T) {
	assertInvariantPlaceholder(t, ErrInvariantI4NotImplemented, "I4")
}

func TestInvariantI5Placeholder(t *testing.T) {
	assertInvariantPlaceholder(t, ErrInvariantI5NotImplemented, "I5")
}

func TestInvariantI6Placeholder(t *testing.T) {
	assertInvariantPlaceholder(t, ErrInvariantI6NotImplemented, "I6")
}
