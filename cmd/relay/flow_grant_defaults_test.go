package main

import (
	"testing"
	"time"
)

func TestAWSGrantDefaultsRespectRoleMaximum(t *testing.T) {
	if got := grantDurationDefault("credential-ttl", "2h", time.Hour, time.Hour); got != "1h0m0s" {
		t.Fatal(got)
	}
	if got := grantDurationDefault("minimum-remaining", "1h", time.Hour, time.Hour); got != "30m0s" {
		t.Fatal(got)
	}
	if err := validateAWSGrantDuration("credential-ttl", "2h", time.Hour, time.Hour); err == nil {
		t.Fatal("oversized grant accepted")
	}
	if err := validateAWSGrantDuration("credential-ttl", "14m", time.Hour, time.Hour); err == nil {
		t.Fatal("too short grant accepted")
	}
	if err := validateAWSGrantDuration("minimum-remaining", "1h", time.Hour, time.Hour); err == nil {
		t.Fatal("unusable remaining-time requirement accepted")
	}
}
