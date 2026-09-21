package main

import (
	"testing"

	"github.com/zksecurity/relay/internal/access"
)

func TestWorkflowV4GrantTTLUsesReviewedAWSMaximum(t *testing.T) {
	for _, test := range []struct {
		provider, maximum, want string
		valid                   bool
	}{
		{"aws", "1h", "1h", true},
		{"aws", "12h", "12h", true},
		{"aws", "13h", "", false},
		{"aws", "", "", false},
		{"aws", "30m", "", false},
		{"aws", "1h0.5s", "1h", true},
		{"other", "12h", "", false},
		{"r2", "", "1h", true},
	} {
		got, err := workflowV4GrantTTL(access.StorageConfig{Provider: test.provider, GrantRoleMaxTTL: test.maximum})
		if (err == nil) != test.valid || got != test.want {
			t.Fatalf("provider=%s maximum=%s: got %q, %v", test.provider, test.maximum, got, err)
		}
	}
}
