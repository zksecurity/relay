package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Explicitly opt-in: this writes/deletes fresh random probe objects in the two
// selected existing buckets. Never enable it in ordinary CI or infer approval
// merely from the availability of credentials.
func TestR2LiveIsolatedStoragePreflight(t *testing.T) {
	if os.Getenv("RELAY_R2_LIVE_PROBES_APPROVED") != "1" {
		t.Skip("requires explicit approval for live R2 probe writes and cleanup")
	}
	require := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("missing non-secret test setting %s", name)
		}
		return value
	}
	account := require("RELAY_R2_LIVE_ACCOUNT")
	if !validR2Hex(account, 16) {
		t.Fatal("invalid account ID")
	}
	parentPath := require("RELAY_R2_LIVE_PARENT_SECRET_FILE")
	if _, err := readProtectedCredential(parentPath); err != nil {
		t.Fatal("inbox parent credential file unavailable or unsafe")
	}
	parentID, err := readProtectedCredential(require("RELAY_R2_LIVE_PARENT_ID_FILE"))
	if err != nil || !validR2Hex(parentID, 16) {
		t.Fatal("inbox parent ID file unavailable or invalid")
	}
	awsBytes, err := readProtectedCredentialBytes(require("RELAY_R2_LIVE_AWS_FILE"), 1<<20)
	if err != nil {
		t.Fatal("coordinator credential file unavailable or unsafe")
	}
	profiles, err := parseR2CoordinatorProfiles(awsBytes)
	if err != nil {
		t.Fatal("coordinator credential profile could not be parsed")
	}
	profileName := require("RELAY_R2_LIVE_AWS_PROFILE")
	profile, ok := profiles[profileName]
	if !ok {
		t.Fatal("selected R2 coordinator profile not found")
	}
	accounts, control, err := wranglerIdentity()
	if err != nil {
		t.Fatal("authorized Wrangler login unavailable")
	}
	found := false
	for _, a := range accounts {
		found = found || a.ID == account
	}
	if !found {
		t.Fatal("selected account was not returned by the authorized login")
	}
	root := privateRoleTestDir(t)
	work, trust := filepath.Join(root, "work"), filepath.Join(root, "trust")
	for _, dir := range []string{work, trust} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	awsFile, controlFile := filepath.Join(root, "aws"), filepath.Join(root, "control")
	if err := os.WriteFile(awsFile, []byte(fmt.Sprintf("[relay-live-probe]\naws_access_key_id = %s\naws_secret_access_key = %s\n", profile[0], profile[1])), 0600); err != nil {
		t.Fatal("could not stage selected coordinator profile")
	}
	if err := os.WriteFile(controlFile, []byte(control), 0600); err != nil {
		t.Fatal("could not stage privacy credential")
	}
	s := coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", map[string]string{
		"provider": "r2", "region": "auto", "profile": "relay-live-probe", "account-id": account,
		"endpoint": "https://" + account + ".r2.cloudflarestorage.com", "parent-access-key-id": parentID,
		"published-bucket": require("RELAY_R2_LIVE_PUBLISHED_BUCKET"), "inbox-bucket": require("RELAY_R2_LIVE_INBOX_BUCKET"), "published-base-url": require("RELAY_R2_LIVE_PUBLIC_URL"),
	}}
	if _, err := s.infrastructure(); err != nil {
		t.Fatal(err)
	}
	if err := setupWriteNew(filepath.Join(work, "settings.json"), s); err != nil {
		t.Fatal(err)
	}
	o := dockerRoleOptions{role: "coordinator", image: require("RELAY_ROLE_ONLINE_IMAGE"), platform: require("RELAY_ROLE_PLATFORM"), work: work, trust: trust, credentials: awsFile, r2Parent: parentPath, r2Control: controlFile}
	args, err := dockerRoleArgs(o, []string{"relay", "coordinator", "check-storage", "--settings", "/work/settings.json", "--out", "/work/checked.json"}, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	if err := client.BindHost(endpoint).Attached(os.Stdout, os.Stderr, args...); err != nil {
		t.Fatal("live preflight failed; inspect the reported probe locations before retrying")
	}
	var receipt infrastructureReceipt
	if err := setupReadJSON(filepath.Join(work, "checked.json"), &receipt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(receipt.Checks, " "), "expired grant denied") {
		t.Fatal("missing scope/expiry checks")
	}
	t.Logf("live checks completed at %s; random probe deletion confirmed, not credential erasure or future permission assurance", receipt.CheckedAt)
}
