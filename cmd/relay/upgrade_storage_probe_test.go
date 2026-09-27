package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
)

func TestUpgradeSupersededStorageProbe(t *testing.T) {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	if err := os.MkdirAll(filepath.Join(work, "coordinator-setup"), 0700); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	base := guidedProfile{Schema: guidedSchema, Name: "current-coordinator", Role: "coordinator", ReleaseCommit: strings.Repeat("b", 40), Work: work}
	failed := upgradeRelatedProfile{dir: filepath.Join(root, "prep-infrastructure-old", "coordinator"), profile: base}
	failed.profile.Name = "prep-infrastructure-old"
	failed.profile.Command = []string{"relay", "coordinator", "check-storage", "--settings", "/work/coordinator-setup/infrastructure-" + id + ".json", "--out", "/work/coordinator-setup/infrastructure-" + id + ".checked.json"}
	later := upgradeRelatedProfile{dir: filepath.Join(root, "prep-storage-new", "coordinator"), profile: base}
	later.profile.Name = "prep-storage-new"
	current := access.StorageConfig{
		Schema: access.StorageConfigSchema, Provider: "aws", CeremonyID: "sha256:" + strings.Repeat("c", 64),
		Region: "us-east-1", PublishedBucket: "published-bucket", PublishedBaseURL: "https://correct.example",
		InboxBucket: "private-inbox", CoordinatorProfile: "relay-coordinator", IssuerProfile: "relay-issuer",
		GrantRoleARN: "arn:aws:iam::123456789012:role/grants", GrantRoleMaxTTL: "1h",
		CeremonyPath: "/work/ceremony/public/ceremony.json", CeremonySignature: "/work/ceremony/public/ceremony.sig",
		CoordinatorPublicKey: "/trust/setup-coordinator.hex", CeremonyBinary: "mpc-ceremony",
	}
	if err := current.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(work, "ceremony", "config"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONNoReplace(filepath.Join(work, "ceremony", "config", "relay-storage.json"), current, 0600); err != nil {
		t.Fatal(err)
	}
	oldSettings := coordinatorStorageSettings{Schema: "relay-coordinator-storage-settings-v1", Settings: map[string]string{
		"provider": "aws", "region": current.Region, "published-bucket": current.PublishedBucket,
		"published-base-url": "https://mistyped.example", "inbox-bucket": current.InboxBucket,
		"profile": current.CoordinatorProfile, "issuer-profile": current.IssuerProfile,
		"grant-role-arn": current.GrantRoleARN, "grant-role-max-ttl": current.GrantRoleMaxTTL,
	}}
	if err := writeJSONNoReplace(filepath.Join(work, "coordinator-setup", "infrastructure-"+id+".json"), oldSettings, 0600); err != nil {
		t.Fatal(err)
	}
	later.profile.Command = []string{
		"relay", "coordinator", "configure-storage", "--home", "/work/ceremony", "--coordinator-key", "/trust/setup-coordinator.hex",
		"--out", "/work/ceremony/config/relay-storage.json", "--provider", current.Provider,
		"--region", current.Region, "--published-bucket", current.PublishedBucket,
		"--published-base-url", current.PublishedBaseURL, "--inbox-bucket", current.InboxBucket,
		"--profile", current.CoordinatorProfile, "--issuer-profile", current.IssuerProfile,
		"--grant-role-arn", current.GrantRoleARN, "--grant-role-max-ttl", current.GrantRoleMaxTTL,
	}
	writeAttempt := func(dir, completed string, success bool) {
		t.Helper()
		activity := filepath.Join(dir, "activity")
		if err := os.MkdirAll(activity, 0700); err != nil {
			t.Fatal(err)
		}
		if err := writeJSONNoReplace(filepath.Join(activity, "attempt-1.json"), guidedAttempt{StartedAt: "2026-09-01T00:00:00Z"}, 0600); err != nil {
			t.Fatal(err)
		}
		if err := writeJSONNoReplace(filepath.Join(activity, "attempt-1.json.done"), guidedAttempt{StartedAt: "2026-09-01T00:00:00Z", CompletedAt: completed, Success: success}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeAttempt(failed.dir, "2026-09-01T00:01:00Z", false)
	writeAttempt(later.dir, "2026-09-02T00:01:00Z", true)
	for _, saved := range []upgradeRelatedProfile{failed, later} {
		if err := writeJSONNoReplace(filepath.Join(saved.dir, "profile.json"), saved.profile, 0600); err != nil {
			t.Fatal(err)
		}
	}
	activity := filepath.Join(failed.dir, "activity")
	if !upgradeSupersededStorageProbe(base, failed, activity, []upgradeRelatedProfile{failed, later}) {
		t.Fatal("corrected, successfully configured ceremony did not supersede old failed setup probe")
	}
	release, err := upgradeV2LockRelated(base, root, "")
	if err != nil {
		t.Fatalf("upgrade admission rejected superseded setup probe: %v", err)
	}
	release()
	// The operator may retry the mistyped saved check after the corrected
	// configuration was recorded. That retry does not undo the configuration.
	if err := writeJSONNoReplace(filepath.Join(activity, "attempt-2.json"), guidedAttempt{StartedAt: "2026-09-03T00:00:00Z"}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONNoReplace(filepath.Join(activity, "attempt-2.json.done"), guidedAttempt{StartedAt: "2026-09-03T00:00:00Z", CompletedAt: "2026-09-03T00:01:00Z", Success: false}, 0600); err != nil {
		t.Fatal(err)
	}
	if !upgradeSupersededStorageProbe(base, failed, activity, []upgradeRelatedProfile{failed, later}) {
		t.Fatal("a failed retry after configuration incorrectly blocked upgrade")
	}
	if upgradeSupersededStorageProbe(base, failed, activity, []upgradeRelatedProfile{failed}) {
		t.Fatal("failed probe was accepted without later configuration")
	}
	otherAction := failed
	otherAction.profile.Command = append([]string(nil), failed.profile.Command...)
	otherAction.profile.Command[2] = "publish"
	if upgradeSupersededStorageProbe(base, otherAction, activity, []upgradeRelatedProfile{otherAction, later}) {
		t.Fatal("failed non-storage action was accepted")
	}
	receipt := filepath.Join(work, "coordinator-setup", "infrastructure-"+id+".checked.json")
	if err := os.WriteFile(receipt, []byte("unexpected"), 0600); err != nil {
		t.Fatal(err)
	}
	if upgradeSupersededStorageProbe(base, failed, activity, []upgradeRelatedProfile{failed, later}) {
		t.Fatal("failed probe with retained output was accepted")
	}
	if err := os.Remove(receipt); err != nil {
		t.Fatal(err)
	}
	wrong := later
	wrong.profile.Work = filepath.Join(root, "other")
	if upgradeSupersededStorageProbe(base, failed, activity, []upgradeRelatedProfile{failed, wrong}) {
		t.Fatal("configuration from another work folder superseded failed probe")
	}
	wrong = later
	wrong.profile.Command = append([]string(nil), later.profile.Command...)
	for i := range wrong.profile.Command {
		if wrong.profile.Command[i] == current.PublishedBaseURL {
			wrong.profile.Command[i] = "https://another.example"
		}
	}
	if upgradeSupersededStorageProbe(base, failed, activity, []upgradeRelatedProfile{failed, wrong}) {
		t.Fatal("configuration for another public URL superseded failed probe")
	}
	if err := os.Remove(filepath.Join(later.dir, "activity", "attempt-1.json.done")); err != nil {
		t.Fatal(err)
	}
	if upgradeSupersededStorageProbe(base, failed, activity, []upgradeRelatedProfile{failed, later}) {
		t.Fatal("incomplete later configuration superseded failed probe")
	}
	if err := writeJSONNoReplace(filepath.Join(later.dir, "activity", "attempt-1.json.done"), guidedAttempt{StartedAt: "2026-09-02T00:00:00Z", CompletedAt: "2026-09-02T00:01:00Z", Success: true}, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(activity, "attempt-1.json.done")); err != nil {
		t.Fatal(err)
	}
	if upgradeSupersededStorageProbe(base, failed, activity, []upgradeRelatedProfile{failed, later}) {
		t.Fatal("missing completion marker accepted")
	}
	if release, err := upgradeV2LockRelated(base, root, ""); err == nil {
		release()
		t.Fatal("upgrade admitted a missing completion marker")
	}
}
