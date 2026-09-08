package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Infrastructure-only live lane. STS scope and actual expiry require a separate
// grant test; do not report those as verified by this storage receipt.
func TestAWSLiveIsolatedStoragePreflight(t *testing.T) {
	if os.Getenv("RELAY_AWS_LIVE_PROBES_APPROVED") != "1" {
		t.Skip("requires explicit approval and dedicated AWS S3 test configuration")
	}
	require := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			t.Fatalf("missing test setting %s", name)
		}
		return value
	}
	var settings coordinatorStorageSettings
	if err := setupReadJSON(require("RELAY_AWS_LIVE_SETTINGS_FILE"), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.Settings["provider"] != "aws" {
		t.Fatal("live AWS test requires AWS settings, not an S3-compatible provider")
	}
	if _, err := settings.infrastructure(); err != nil {
		t.Fatal(err)
	}
	credentials := require("RELAY_AWS_LIVE_CREDENTIALS_FILE")
	if _, err := readProtectedCredentialBytes(credentials, 1<<20); err != nil {
		t.Fatal("dedicated AWS credentials file unavailable or unsafe")
	}
	root := privateRoleTestDir(t)
	work, trust := filepath.Join(root, "work"), filepath.Join(root, "trust")
	for _, dir := range []string{work, trust} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := setupWriteNew(filepath.Join(work, "settings.json"), settings); err != nil {
		t.Fatal(err)
	}
	o := dockerRoleOptions{role: "coordinator", image: require("RELAY_ROLE_ONLINE_IMAGE"), platform: require("RELAY_ROLE_PLATFORM"), work: work, trust: trust, credentials: credentials}
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
		t.Fatal("live AWS preflight failed; inspect reported probe locations before retrying")
	}
	var receipt infrastructureReceipt
	if err := setupReadJSON(filepath.Join(work, "checked.json"), &receipt); err != nil {
		t.Fatal(err)
	}
	digest, err := setupFileHash(filepath.Join(work, "settings.json"))
	if err != nil || receipt.SettingsSHA256 != digest || receipt.Schema != "relay-infrastructure-check-v1" {
		t.Fatal("storage receipt does not match the tested settings")
	}
	t.Logf("AWS storage checks completed at %s; this lane does not establish STS grant scope, actual expiry or future permissions", receipt.CheckedAt)
}
