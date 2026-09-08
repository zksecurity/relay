package main

import (
	"fmt"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func grantDurationDefault(flag, current string, maximum, ttl time.Duration) string {
	value, err := time.ParseDuration(current)
	if flag == "credential-ttl" && (err != nil || value > maximum || value < 15*time.Minute) {
		return maximum.String()
	}
	if flag == "minimum-remaining" && (err != nil || value >= ttl || value <= 0) {
		return (ttl / 2).String()
	}
	return current
}

func (f *roleFlow) awsGrantMaximum(command []string) (time.Duration, error) {
	if f.state.Profile.Work == "" {
		return 0, nil
	}
	value := commandValue(command, "storage")
	if value == "" {
		return 0, nil
	}
	local, err := f.publicHostPath(value)
	if err != nil {
		return 0, err
	}
	var c access.StorageConfig
	if err := setupReadJSON(local, &c); err != nil {
		return 0, err
	}
	if err := c.Validate(); err != nil {
		return 0, err
	}
	if c.Provider != "aws" {
		return 0, nil
	}
	return time.ParseDuration(c.GrantRoleMaxTTL)
}

func validateAWSGrantDuration(flag, value string, maximum, ttl time.Duration) error {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return fmt.Errorf("enter a positive duration, such as 30m")
	}
	if flag == "credential-ttl" && (duration < 15*time.Minute || duration > maximum) {
		return fmt.Errorf("AWS grant lifetime must be between 15m and %s", maximum)
	}
	if flag == "minimum-remaining" && duration >= ttl {
		return fmt.Errorf("minimum remaining time must be less than the %s grant lifetime", ttl)
	}
	return nil
}
