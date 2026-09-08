package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/store"
)

// Dedicated-account opt-in. Only fresh synthetic keys are read or written.
// Run inside the AWS CLI container; credentials never enter Docker Env or logs.
func TestAWSLiveGrantScopeAndExpiry(t *testing.T) {
	if os.Getenv("RELAY_AWS_LIVE_GRANT_APPROVED") != "1" {
		t.Skip("requires dedicated AWS test approval")
	}
	var settings coordinatorStorageSettings
	if err := setupReadJSON(os.Getenv("RELAY_AWS_LIVE_SETTINGS_FILE"), &settings); err != nil {
		t.Fatal(err)
	}
	config, err := settings.infrastructure()
	if err != nil {
		t.Fatal(err)
	}
	requireAWSLiveConfiguration(t, config)
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	base := "setup-probes/" + id + "/"
	t.Logf("Synthetic probe prefix: %s", base)
	creds, expires, err := issueAWS(config, "scope-expiry-test", base+"allowed/", 15*time.Minute)
	if err != nil {
		t.Fatal("could not issue temporary grant")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	data := []byte("Relay synthetic AWS grant check\n")
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	owner := coordinatorClient(config, config.InboxBucket)
	public := coordinatorClient(config, config.PublishedBucket)
	scoped := store.Client{Region: config.Region, Bucket: config.InboxBucket, Credentials: &store.Credentials{AccessKeyID: creds.AccessKeyID, SecretAccessKey: creds.SecretAccessKey, SessionToken: creds.SessionToken}}
	type object struct {
		client store.Client
		key    string
	}
	var created []object
	defer func() {
		for _, p := range created {
			if err := p.client.Delete(p.key); err != nil {
				t.Errorf("cleanup unresolved: %s/%s", p.client.Bucket, p.key)
			}
		}
	}()
	put := func(writer, cleaner store.Client, key string) {
		t.Helper()
		if err := writer.PutNoReplace(key, source); err != nil {
			t.Fatalf("write failed; inspect exact key %s/%s before retry", writer.Bucket, key)
		}
		created = append(created, object{cleaner, key})
	}
	put(scoped, owner, base+"allowed/probe")
	allowed := filepath.Join(dir, "allowed")
	if err := scoped.Get(base+"allowed/probe", allowed); err != nil {
		t.Fatal("allowed read failed")
	}
	got, err := os.ReadFile(allowed)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("allowed bytes differ")
	}
	for _, cleaner := range []store.Client{owner, public} {
		put(cleaner, cleaner, base+"outside/probe")
		denied := scoped
		denied.Bucket = cleaner.Bucket
		if err := denied.Get(base+"outside/probe", filepath.Join(dir, cleaner.Bucket)); err == nil || !isAccessDenied(err) {
			t.Fatal("outside read not conclusively denied")
		}
		key := base + "outside/write"
		err := denied.PutNoReplace(key, source)
		if err == nil {
			created = append(created, object{cleaner, key})
			t.Fatal("outside write unexpectedly succeeded")
		}
		if !isAccessDenied(err) {
			t.Fatalf("outside write inconclusive; inspect %s/%s", cleaner.Bucket, key)
		}
	}
	t.Logf("Allowed read/write and outside-prefix/other-bucket denial passed; waiting until %s", expires.Add(5*time.Second).UTC().Format(time.RFC3339))
	for time.Now().Before(expires.Add(5 * time.Second)) {
		remaining := time.Until(expires.Add(5 * time.Second))
		if remaining > 30*time.Second {
			remaining = 30 * time.Second
		}
		time.Sleep(remaining)
	}
	// Prove the object still exists using coordinator credentials before checking expiry.
	if err := owner.Get(base+"allowed/probe", filepath.Join(dir, "owner-after-expiry")); err != nil {
		t.Fatal("coordinator control read failed")
	}
	err = scoped.Get(base+"allowed/probe", filepath.Join(dir, "expired"))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "expiredtoken") {
		t.Fatal("AWS did not explicitly reject the expired token")
	}
	t.Log("AWS explicitly rejected the expired token; coordinator control read succeeded")
}
