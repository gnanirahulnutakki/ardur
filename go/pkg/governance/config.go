package governance

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddr      string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// AuthToken is the bearer token required on every /v1/* endpoint
	// (FIX-R5-H2 from round-4 audit, 2026-04-29). Loaded from
	// ``ARDUR_GOVERNOR_TOKEN``. When empty, RequireAuth must be false
	// or :func:`Validate` refuses to start the server.
	AuthToken []byte

	// RequireAuth gates the bearer-token check. Default true; setting
	// ``ARDUR_GOVERNOR_NO_REQUIRE_AUTH=1`` flips it to false ONLY for
	// local development. Production deployments MUST keep this true.
	RequireAuth bool
}

func DefaultConfig() Config {
	return Config{
		ListenAddr:      ":8080",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 15 * time.Second,
		RequireAuth:     true,
	}
}

func LoadFromEnv() Config {
	cfg := DefaultConfig()

	if v := os.Getenv("GOVERNOR_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := os.Getenv("GOVERNOR_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ReadTimeout = d
		}
	}
	if v := os.Getenv("GOVERNOR_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.WriteTimeout = d
		}
	}
	if v := os.Getenv("GOVERNOR_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.IdleTimeout = d
		}
	}
	if v := os.Getenv("GOVERNOR_SHUTDOWN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ShutdownTimeout = d
		}
	}
	if v := os.Getenv("ARDUR_GOVERNOR_TOKEN"); v != "" {
		// Round-8 FIX-R8-3 (2026-04-29): TrimSpace symmetric with the
		// Authority's main(). Round-7 audit (LOW-NEW-1) flagged that a
		// whitespace-padded env var would leave 32+ bytes of whitespace
		// as the "token" — Validate() would accept the length floor,
		// but no client-presented Bearer token could match because the
		// handler trims the bearer payload. Service silently becomes
		// unreachable. Trim here so the env-loaded token matches what
		// the bearer-auth path actually compares against.
		cfg.AuthToken = []byte(strings.TrimSpace(v))
	}
	if v := os.Getenv("ARDUR_GOVERNOR_NO_REQUIRE_AUTH"); v == "1" || v == "true" {
		cfg.RequireAuth = false
	}

	return cfg
}

func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("governance config: listen address must not be empty")
	}
	if c.ReadTimeout <= 0 {
		return fmt.Errorf("governance config: read timeout must be positive")
	}
	if c.WriteTimeout <= 0 {
		return fmt.Errorf("governance config: write timeout must be positive")
	}
	if c.IdleTimeout <= 0 {
		return fmt.Errorf("governance config: idle timeout must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("governance config: shutdown timeout must be positive")
	}
	// FIX-R5-H2 (2026-04-29): refuse to start when auth is required
	// but no token is supplied. Production deployments MUST set
	// ARDUR_GOVERNOR_TOKEN; --no-require-auth (env-driven) is the only
	// supported opt-out for local development.
	//
	// Round-7 FIX-R7-6: the error message is honest — we check byte
	// length, not entropy. A 32-character passphrase passes the floor;
	// operator responsibility to use a CSPRNG-derived value.
	if c.RequireAuth {
		if len(c.AuthToken) == 0 {
			return fmt.Errorf(
				"governance config: ARDUR_GOVERNOR_TOKEN is required " +
					"(set ARDUR_GOVERNOR_NO_REQUIRE_AUTH=1 only for local " +
					"dev; production /v1/* endpoints MUST authenticate)")
		}
		if len(c.AuthToken) < 32 {
			return fmt.Errorf(
				"governance config: ARDUR_GOVERNOR_TOKEN must be at " +
					"least 32 bytes long (e.g. `openssl rand -hex 32`). " +
					"NOTE: length is a floor, not entropy — generate the " +
					"token from a CSPRNG, not a passphrase")
		}
	}
	return nil
}
