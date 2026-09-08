package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
)

func requireAWSLiveConfiguration(t *testing.T, c access.StorageConfig) {
	t.Helper()
	account := os.Getenv("RELAY_AWS_LIVE_EXPECTED_ACCOUNT")
	if len(account) != 12 || strings.Trim(account, "0123456789") != "" {
		t.Fatal("explicit expected AWS test account required")
	}
	if c.Provider != "aws" || !strings.HasPrefix(c.GrantRoleARN, "arn:aws:iam::"+account+":role/relay-test-") || !strings.HasPrefix(c.InboxBucket, "relay-test-") || !strings.HasPrefix(c.PublishedBucket, "relay-test-") || c.InboxBucket == c.PublishedBucket {
		t.Fatal("use explicitly approved relay-test resources in the expected account")
	}
}

// Local opt-in helper: refresh through the isolated personal-account CLI, never
// through the operator's default AWS profile. Values are never logged.
func freshAWSLiveCredentials(t *testing.T) string {
	t.Helper()
	wrapper := os.Getenv("RELAY_AWS_TEST_CLI")
	if !filepath.IsAbs(wrapper) || filepath.Clean(wrapper) != wrapper {
		t.Fatal("explicit isolated test CLI required")
	}
	raw, err := exec.Command(wrapper, "sts", "get-caller-identity").Output()
	if err != nil {
		t.Fatal("test login unavailable")
	}
	var identity struct{ Account, Arn string }
	if json.Unmarshal(raw, &identity) != nil || identity.Account != os.Getenv("RELAY_AWS_LIVE_EXPECTED_ACCOUNT") || identity.Arn != os.Getenv("RELAY_AWS_LIVE_EXPECTED_PRINCIPAL") || !strings.HasPrefix(identity.Arn, "arn:aws:iam::"+identity.Account+":user/") {
		t.Fatal("wrong AWS test identity")
	}
	raw, err = exec.Command(wrapper, "configure", "export-credentials", "--profile", "relay-aws-test", "--format", "process").Output()
	if err != nil {
		t.Fatal("test credential refresh failed")
	}
	var c struct{ AccessKeyId, SecretAccessKey, SessionToken string }
	if json.Unmarshal(raw, &c) != nil || c.AccessKeyId == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		t.Fatal("invalid temporary credentials")
	}
	file := filepath.Join(privateRoleTestDir(t), "aws")
	if err := os.WriteFile(file, []byte(fmt.Sprintf("[relay-aws-test]\naws_access_key_id=%s\naws_secret_access_key=%s\naws_session_token=%s\n", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)), 0600); err != nil {
		t.Fatal("could not stage temporary test session")
	}
	return file
}
