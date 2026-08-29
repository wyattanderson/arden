package main

import (
	"errors"
	"fmt"
	"os"
	"time"
)

const defaultTimeout = 30 * time.Second

type configuration struct {
	address    string
	serverName string
	caFile     string
	stableID   string
	timeout    time.Duration
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		address:    os.Getenv("ARDEN_ADDRESS"),
		serverName: os.Getenv("ARDEN_SERVER_NAME"),
		caFile:     os.Getenv("ARDEN_CA_FILE"),
		stableID:   os.Getenv("ARDEN_IDENTITY"),
		timeout:    defaultTimeout,
	}
	if config.stableID == "" {
		config.stableID = "freeipa-compose-client"
	}
	if value := os.Getenv("ARDEN_TIMEOUT"); value != "" {
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return configuration{}, fmt.Errorf("parse ARDEN_TIMEOUT: %w", err)
		}
		config.timeout = timeout
	}
	if config.address == "" {
		return configuration{}, errors.New("ARDEN_ADDRESS is required")
	}
	if config.serverName == "" {
		return configuration{}, errors.New("ARDEN_SERVER_NAME is required")
	}
	if config.caFile == "" {
		return configuration{}, errors.New("ARDEN_CA_FILE is required")
	}
	if config.timeout <= 0 {
		return configuration{}, errors.New("ARDEN_TIMEOUT must be positive")
	}
	return config, nil
}
