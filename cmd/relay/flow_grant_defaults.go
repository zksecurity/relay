package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

type flowGrantLimits struct {
	provider         string
	minimum, maximum time.Duration
}

func displayGrantDuration(d time.Duration) string {
	s := d.String()
	if d >= time.Minute && d%time.Minute == 0 {
		s = strings.TrimSuffix(s, "0s")
	}
	if d >= time.Hour && d%time.Hour == 0 {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func (l flowGrantLimits) defaultValue(flag, current string, ttl time.Duration) string {
	value, err := time.ParseDuration(current)
	if flag == "credential-ttl" && (err != nil || value > l.maximum || value < l.minimum || value%time.Second != 0) {
		return displayGrantDuration(l.maximum)
	}
	if flag == "minimum-remaining" && (err != nil || value >= ttl || value <= 0) {
		return displayGrantDuration(ttl / 2)
	}
	return current
}

func (f *roleFlow) grantLimits(command []string) (flowGrantLimits, error) {
	var empty flowGrantLimits
	if f.state.Profile.Work == "" {
		return empty, nil
	}
	value := commandValue(command, "storage")
	if value == "" {
		return empty, nil
	}
	local, err := f.publicHostPath(value)
	if err != nil {
		return empty, err
	}
	var c access.StorageConfig
	if err := setupReadJSON(local, &c); err != nil {
		return empty, err
	}
	if err := c.Validate(); err != nil {
		return empty, err
	}
	if c.Provider == "r2" {
		// Match runGrant/issueR2: positive whole seconds, at most seven days.
		return flowGrantLimits{"R2", time.Second, 168 * time.Hour}, nil
	}
	maximum, err := time.ParseDuration(c.GrantRoleMaxTTL)
	// Issuance accepts whole seconds, even if an imported maximum has a fraction.
	return flowGrantLimits{"AWS", 15 * time.Minute, maximum.Truncate(time.Second)}, err
}

func (l flowGrantLimits) label(flag, label string, ttl time.Duration) string {
	if flag == "credential-ttl" {
		return fmt.Sprintf("%s (%s configured range: %s to %s, inclusive; whole seconds)", label, l.provider, displayGrantDuration(l.minimum), displayGrantDuration(l.maximum))
	}
	return fmt.Sprintf("%s (more than 0 and less than %s)", label, displayGrantDuration(ttl))
}

func (l flowGrantLimits) validate(flag, value string, ttl time.Duration) error {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return fmt.Errorf("enter a positive duration, such as 30m")
	}
	if flag == "credential-ttl" && (duration < l.minimum || duration > l.maximum || duration%time.Second != 0) {
		return fmt.Errorf("%s grant lifetime must be between %s and %s inclusive, in whole seconds", l.provider, displayGrantDuration(l.minimum), displayGrantDuration(l.maximum))
	}
	if flag == "minimum-remaining" && duration >= ttl {
		return fmt.Errorf("minimum remaining time must be less than the %s grant lifetime", displayGrantDuration(ttl))
	}
	return nil
}
