package governance

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8080")
	}
	if cfg.ReadTimeout != 5*time.Second {
		t.Errorf("ReadTimeout = %v, want %v", cfg.ReadTimeout, 5*time.Second)
	}
	if cfg.WriteTimeout != 10*time.Second {
		t.Errorf("WriteTimeout = %v, want %v", cfg.WriteTimeout, 10*time.Second)
	}
	if cfg.IdleTimeout != 120*time.Second {
		t.Errorf("IdleTimeout = %v, want %v", cfg.IdleTimeout, 120*time.Second)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 15*time.Second)
	}
	if !cfg.RequireAuth {
		t.Error("RequireAuth = false on defaults; FIX-R5-H2 requires auth-on by default")
	}
	// FIX-R5-H2: Validate() now refuses to start without a token when
	// RequireAuth is true (the default). DefaultConfig alone is therefore
	// expected to reject — operators must either set ARDUR_GOVERNOR_TOKEN
	// or set ARDUR_GOVERNOR_NO_REQUIRE_AUTH=1.
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() on defaults must reject without an AuthToken (FIX-R5-H2)")
	}
	// Supplying a long-enough token makes the same defaults pass.
	cfg.AuthToken = []byte("this-is-a-32-byte-test-token-abcd")
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() on defaults+token returned error: %v", err)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("GOVERNOR_LISTEN_ADDR", ":9090")
	t.Setenv("GOVERNOR_READ_TIMEOUT", "3s")
	t.Setenv("GOVERNOR_WRITE_TIMEOUT", "7s")
	t.Setenv("GOVERNOR_IDLE_TIMEOUT", "60s")
	t.Setenv("GOVERNOR_SHUTDOWN_TIMEOUT", "5s")

	cfg := LoadFromEnv()

	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9090")
	}
	if cfg.ReadTimeout != 3*time.Second {
		t.Errorf("ReadTimeout = %v, want %v", cfg.ReadTimeout, 3*time.Second)
	}
	if cfg.WriteTimeout != 7*time.Second {
		t.Errorf("WriteTimeout = %v, want %v", cfg.WriteTimeout, 7*time.Second)
	}
	if cfg.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout = %v, want %v", cfg.IdleTimeout, 60*time.Second)
	}
	if cfg.ShutdownTimeout != 5*time.Second {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, 5*time.Second)
	}
}

func TestLoadFromEnvInvalidDuration(t *testing.T) {
	t.Setenv("GOVERNOR_READ_TIMEOUT", "not-a-duration")

	cfg := LoadFromEnv()

	if cfg.ReadTimeout != 5*time.Second {
		t.Errorf("ReadTimeout = %v, want default %v when env is invalid", cfg.ReadTimeout, 5*time.Second)
	}
}

func TestConfigValidateErrors(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Config)
	}{
		{"empty listen addr", func(c *Config) { c.ListenAddr = "" }},
		{"zero read timeout", func(c *Config) { c.ReadTimeout = 0 }},
		{"negative write timeout", func(c *Config) { c.WriteTimeout = -1 }},
		{"zero idle timeout", func(c *Config) { c.IdleTimeout = 0 }},
		{"zero shutdown timeout", func(c *Config) { c.ShutdownTimeout = 0 }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			// Supply a valid auth token so the existing per-field
			// validation cases (read/write/idle/shutdown timeout) are
			// what's exercised, not the FIX-R5-H2 missing-token gate.
			cfg.AuthToken = []byte("this-is-a-32-byte-test-token-abcd")
			tt.modify(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Error("Validate() should return error")
			}
		})
	}
}

// FIX-R9-3 (round-9, 2026-04-29): pin the TrimSpace behaviour added
// by R8-3. Round-8 audit (LOW-NEW-2) caught that R8-3's whitespace-
// stripping fix shipped without a regression test: a revert from
// ``[]byte(strings.TrimSpace(v))`` to ``[]byte(v)`` would silently
// reopen the operator-confusion failure mode where a YAML-quoted
// secret with leading/trailing whitespace would pass the length
// floor but fail every client-presented Bearer token comparison.
func TestLoadFromEnvTrimsAuthToken(t *testing.T) {
	t.Setenv("ARDUR_GOVERNOR_TOKEN", "  this-is-a-32-byte-test-token-abcd  ")
	cfg := LoadFromEnv()
	if got := string(cfg.AuthToken); got != "this-is-a-32-byte-test-token-abcd" {
		t.Errorf("AuthToken = %q, want trimmed %q",
			got, "this-is-a-32-byte-test-token-abcd")
	}
}

// FIX-R5-H2 (round-5, 2026-04-29): explicitly pin the auth-required
// validation. A regression that flipped RequireAuth's default to false,
// or that removed the token-length check, would not fail the existing
// timeout-focused tests above.
func TestConfigValidateRequiresAuthToken(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() must reject when RequireAuth=true and no token")
	}
	cfg.AuthToken = []byte("too-short")
	if err := cfg.Validate(); err == nil {
		t.Error("Validate() must reject sub-32-byte tokens")
	}
	cfg.AuthToken = []byte("this-is-a-32-byte-test-token-abcd")
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() must accept a 32+ byte token; got %v", err)
	}
	// Explicit opt-out path: RequireAuth=false → no token needed.
	optOut := DefaultConfig()
	optOut.RequireAuth = false
	if err := optOut.Validate(); err != nil {
		t.Errorf("Validate() must accept RequireAuth=false; got %v", err)
	}
}
