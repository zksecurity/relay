package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const awsSetupIdentity = `{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/ceremony","UserId":"AIDASYNTHETIC"}`
const awsSetupSecret = "syntheticSecretNeverInLogs"

func awsSetupFixture(t *testing.T, input string) *coordinatorWizard {
	t.Helper()
	w := setupFixture(t)
	w.credentialRoot = t.TempDir()
	if err := os.Chmod(w.credentialRoot, 0700); err != nil {
		t.Fatal(err)
	}
	w.input = bufio.NewReader(strings.NewReader(input))
	w.awsSetupRun = func(_ context.Context, binary string, args []string, progress io.Writer) ([]byte, error) {
		if binary != "aws" || progress != nil {
			t.Fatal("unexpected provisioning", binary, args)
		}
		switch strings.Join(args, " ") {
		case "configure list-profiles":
			return []byte("test-account\n"), nil
		case "--profile test-account --region us-east-1 sts get-caller-identity --output json":
			return []byte(awsSetupIdentity), nil
		case "--profile test-account configure get region":
			return []byte("us-east-1\n"), nil
		case "configure export-credentials --profile test-account --region us-east-1 --format process":
			return []byte(`{"Version":1,"AccessKeyId":"TESTACCESS","SecretAccessKey":"` + awsSetupSecret + `"}`), nil
		case "--profile test-account --region us-east-1 sts get-session-token --duration-seconds 43200 --output json":
			return []byte(`{"Credentials":{"AccessKeyId":"TEMPACCESS","SecretAccessKey":"TEMPSECRET","SessionToken":"TEMPTOKEN","Expiration":"` + time.Now().Add(12*time.Hour).UTC().Format(time.RFC3339) + `"}}`), nil
		default:
			t.Fatal("unexpected AWS command", args)
			return nil, nil
		}
	}
	return &w
}

func TestAWSGuidedExistingStorage(t *testing.T) {
	w := awsSetupFixture(t, "1\nUSE ACCOUNT\n1\n\npublic-fixture\nprivate-fixture\nhttps://ceremony.example\narn:aws:iam::123456789012:role/grants\n\nSAVE SETTINGS\n")
	if err := w.setupAWS(); err != nil {
		t.Fatal(err)
	}
	if w.d.Storage["profile"] != "relay-coordinator" || w.d.Storage["issuer-profile"] != "relay-coordinator" {
		t.Fatal("wrong runtime profiles")
	}
	raw, err := os.ReadFile(w.d.Credentials)
	if err != nil || bytes.Contains(raw, []byte(awsSetupSecret)) || !bytes.Contains(raw, []byte(awsLoginSchemaV2)) {
		t.Fatal("missing protected IAM-user host binding or copied static secret", err)
	}
	st, _ := os.Stat(w.d.Credentials)
	if st.Mode().Perm() != 0600 {
		t.Fatal("credentials permissions")
	}
	draft, _ := os.ReadFile(w.draftPath)
	if bytes.Contains(draft, []byte(awsSetupSecret)) || strings.Contains(w.output.(*bytes.Buffer).String(), awsSetupSecret) {
		t.Fatal("secret leaked into draft or output")
	}
	if !strings.Contains(w.output.(*bytes.Buffer).String(), "Next: Check storage") {
		t.Fatal("missing check guidance")
	}
}

func TestAWSGuidedDeclineAndRootMakeNoChanges(t *testing.T) {
	for _, root := range []bool{false, true} {
		w := awsSetupFixture(t, "1\nno\n")
		original := w.awsSetupRun
		w.awsSetupRun = func(ctx context.Context, bin string, args []string, output io.Writer) ([]byte, error) {
			if root && strings.Contains(strings.Join(args, " "), "get-caller-identity") {
				return []byte(`{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:root"}`), nil
			}
			return original(ctx, bin, args, output)
		}
		before, _ := json.Marshal(w.d)
		if err := w.setupAWS(); err == nil {
			t.Fatal("expected refusal")
		}
		after, _ := json.Marshal(w.d)
		if !bytes.Equal(before, after) {
			t.Fatal("draft changed")
		}
		entries, _ := os.ReadDir(w.credentialRoot)
		if len(entries) != 0 {
			t.Fatal("credentials written")
		}
	}
}

func TestAWSProvisionApprovalAndFailure(t *testing.T) {
	for _, approve := range []bool{false, true} {
		answer := "no"
		if approve {
			answer = "CREATE RESOURCES"
		}
		w := awsSetupFixture(t, "\n"+answer+"\n")
		called := false
		w.awsSetupRun = func(_ context.Context, bin string, args []string, output io.Writer) ([]byte, error) {
			called = true
			if bin != "bash" || output == nil {
				t.Fatal("wrong runner")
			}
			config, err := os.ReadFile(args[3])
			if err != nil || !bytes.Contains(config, []byte("EXPECTED_ACCOUNT='123456789012'")) || !bytes.Contains(config, []byte("EXPECTED_CALLER_ARN='arn:aws:iam::123456789012:user/ceremony'")) {
				t.Fatal("missing reviewed identity pin", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(args[0])) })
			return nil, errors.New("synthetic provisioning interruption")
		}
		before, _ := json.Marshal(w.d)
		if _, err := w.provisionAWS("test-account", "us-east-1", "123456789012", "arn:aws:iam::123456789012:user/ceremony"); err == nil {
			t.Fatal("expected stop")
		}
		after, _ := json.Marshal(w.d)
		if called != approve || !bytes.Equal(before, after) {
			t.Fatal("approval or failure-state regression")
		}
	}
}

func TestAWSGuidedProvisionSuccess(t *testing.T) {
	w := awsSetupFixture(t, "2\n1\nUSE ACCOUNT\n2\n\n\nCREATE RESOURCES\nSAVE SETTINGS\n")
	base := w.awsSetupRun
	provisioned := false
	w.awsSetupRun = func(ctx context.Context, bin string, args []string, output io.Writer) ([]byte, error) {
		if bin != "bash" {
			return base(ctx, bin, args, output)
		}
		provisioned = true
		t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(args[0])) })
		script, err := os.ReadFile(args[0])
		if err != nil || !bytes.Contains(script, []byte("EXPECTED_ACCOUNT")) {
			t.Fatal("wrong embedded script")
		}
		return nil, writeJSONNoReplace(args[2], storageSettingsFixture(), 0600)
	}
	// Exercise the actual top-level menu, not just its AWS helper.
	if err := w.storage(); err != nil {
		t.Fatal(err)
	}
	if !provisioned || w.d.Storage["provider"] != "aws" || w.d.Credentials == "" {
		t.Fatal("provisioning not saved")
	}
	if !strings.Contains(w.output.(*bytes.Buffer).String(), "2) Set up Amazon S3 and credentials") {
		t.Fatal("missing first-class AWS option")
	}
}

func TestAWSSnapshotExpiryAndInjection(t *testing.T) {
	for _, extra := range []string{`,"SessionToken":"TOKEN"`, `,"Expiration":"2000-01-01T00:00:00Z"`, `,"Expiration":"bad"`, `,"SessionToken":"TOKEN\n[evil]"`} {
		if _, _, err := awsSnapshot([]byte(`{"Version":1,"AccessKeyId":"TEST","SecretAccessKey":"SECRET"` + extra + `}`)); err == nil {
			t.Fatal("accepted invalid snapshot", extra)
		}
	}
	expiry := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	text, got, err := awsSnapshot([]byte(`{"Version":1,"AccessKeyId":"TEST","SecretAccessKey":"SECRET","SessionToken":"TOKEN","Expiration":"` + expiry + `"}`))
	if err != nil || got != expiry || !strings.Contains(text, "aws_session_token = TOKEN") {
		t.Fatal("valid snapshot rejected", err)
	}
}

func TestAWSSetupEnvironment(t *testing.T) {
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_ENDPOINT_URL", "BASH_ENV"} {
		t.Setenv(key, "PRIVATE-CANARY")
	}
	if strings.Contains(strings.Join(awsSetupEnvironment(), "\n"), "PRIVATE-CANARY") {
		t.Fatal("unsafe environment inherited")
	}
	var b awsSetupBuffer
	if _, err := io.Copy(&b, strings.NewReader(strings.Repeat("x", 2*1024*1024))); err == nil || b.data.Len() > 1024*1024 {
		t.Fatal("unbounded subprocess output")
	}
}
