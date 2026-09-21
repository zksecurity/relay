package main

import (
	"errors"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

// workflowV4GrantTTL uses the ceremony's reviewed AWS role limit. R2 keeps the
// released one-hour workflow default until its longer lifetime is separately
// reviewed for the storage-first protocol.
func workflowV4GrantTTL(config access.StorageConfig) (string, error) {
	if config.Provider == "r2" {
		return "1h", nil
	}
	if config.Provider != "aws" {
		return "", errors.New("unsupported grant provider")
	}
	ttl, err := time.ParseDuration(config.GrantRoleMaxTTL)
	if err != nil || ttl < time.Hour || ttl > access.MaxStorageFirstGrantLifetime {
		return "", errors.New("AWS grant role maximum must be from 1h through 12h")
	}
	return displayGrantDuration(ttl.Truncate(time.Second)), nil
}
