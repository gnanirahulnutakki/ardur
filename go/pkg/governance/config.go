package governance

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	ListenAddr      string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
}

func DefaultConfig() Config {
	return Config{
		ListenAddr:      ":8080",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    10 * time.Second,
		IdleTimeout:     120 * time.Second,
		ShutdownTimeout: 15 * time.Second,
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
	return nil
}
