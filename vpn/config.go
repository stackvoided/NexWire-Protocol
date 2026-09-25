package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
)

type Config struct {
	Mode           string        `json:"mode"`
	ListenAddr     string        `json:"listen_addr"`
	RemoteAddr     string        `json:"remote_addr"`
	TunName        string        `json:"tun_name"`
	TunIP          string        `json:"tun_ip"`
	PSK            string        `json:"psk"`
	Workers        int           `json:"workers"`
	MTU            int           `json:"mtu"`
	KeyRotationSec time.Duration `json:"key_rotation_sec"`
	KeepaliveSec   time.Duration `json:"keepalive_sec"`
}

func DefaultConfig() *Config {
	return &Config{
		Mode:           "server",
		ListenAddr:     "0.0.0.0:8443",
		TunName:        "vpn0",
		TunIP:          "10.8.0.1/24",
		Workers:        runtime.NumCPU(),
		MTU:            1420,
		KeyRotationSec: 3600,
		KeepaliveSec:   25,
	}
}

func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("config open failed: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config decode failed: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

func (c *Config) Validate() error {
	if c.Mode != "server" && c.Mode != "client" {
		return errors.New("mode must be 'server' or 'client'")
	}
	if c.PSK == "" {
		return errors.New("psk cannot be empty")
	}
	if c.Mode == "client" && c.RemoteAddr == "" {
		return errors.New("remote_addr is required in client mode")
	}
	if _, _, err := net.ParseCIDR(c.TunIP); err != nil {
		return fmt.Errorf("invalid tun_ip CIDR format: %w", err)
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return errors.New("mtu must be between 576 and 9000")
	}
	if c.Workers <= 0 {
		c.Workers = runtime.NumCPU()
	}
	return nil
}
