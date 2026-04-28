package provenance

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// validateSHA256Hex checks that s is a valid hex-encoded SHA-256 digest.
// Accepts both bare hex and "sha256:" prefixed formats.
func validateSHA256Hex(s string) error {
	h := strings.TrimPrefix(s, "sha256:")
	if len(h) != 64 {
		return fmt.Errorf("SHA-256 hex digest must be 64 characters, got %d", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		return fmt.Errorf("invalid hex in SHA-256 digest: %w", err)
	}
	return nil
}
