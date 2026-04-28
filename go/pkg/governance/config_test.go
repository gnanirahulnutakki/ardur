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
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() on defaults returned error: %v", err)
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
			tt.modify(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Error("Validate() should return error")
			}
		})
	}
}
