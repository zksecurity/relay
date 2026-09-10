package main

import (
	"encoding/json"
	setupv2 "github.com/zksecurity/relay/contracts/setupv2r2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStorageConnection() tesseraStorageConnection {
	settings := storageSettingsFixture()
	settings.Settings["profile"] = "tessera"
	settings.Settings["issuer-profile"] = "tessera"
	return tesseraStorageConnection{tesseraConnectionSchema, "a1f340d2-5155-420c-b7b1-272276639b83", "d3680924-6a30-41e0-a129-33fab43912cd", "https://example.test", time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano), "sha256:" + strings.Repeat("a", 64), strings.Repeat("b", 43), settings}
}
func TestTesseraStoragePrivateProfile(t *testing.T) {
	c := testStorageConnection()
	raw, err := connectionProfile(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "aws")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	read, err := readConnectionProfile(path)
	if err != nil || read.Token != c.Token {
		t.Fatal("profile round trip failed")
	}
	if strings.Contains(strings.Split(string(raw), "\n")[1], c.Token) {
		t.Fatal("secret in process command")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readConnectionProfile(path); err == nil {
		t.Fatal("accepted public connection file")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(strings.Replace(string(raw), "/usr/local/bin/relay", "arbitrary-command", 1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readConnectionProfile(path); err == nil {
		t.Fatal("accepted changed credential process")
	}
	for _, origin := range []string{"http://example.test", "https://u:p@example.test", "https://example.test/path", "https://example.test?secret=1"} {
		bad := c
		bad.Origin = origin
		if bad.validate() == nil {
			t.Fatal("accepted unsafe origin")
		}
	}
	c.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if c.validate() == nil {
		t.Fatal("accepted expired connection")
	}
}
func TestTesseraStorageRenewalAndDisconnect(t *testing.T) {
	c := testStorageConnection()
	status := http.StatusOK
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/api/v1/cli-storage/"+c.ConnectionID+"/credentials" || r.Header.Get("Authorization") != "Bearer "+c.Token {
			t.Error("incorrect renewal request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status != http.StatusOK {
			_, _ = w.Write([]byte("sensitive server output must not appear in CLI errors"))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"credentials": tesseraAWSCredentials{1, "ASIA" + strings.Repeat("A", 16), strings.Repeat("b", 40), strings.Repeat("c", 32), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}})
	}))
	defer server.Close()
	c.Origin = server.URL
	client := tesseraStorageClient()
	client.Transport = server.Client().Transport
	if _, err := tesseraConnectionRequest(c, client); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{401, 403, 409, 503} {
		status = code
		_, err := tesseraConnectionRequest(c, client)
		if err == nil || strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), c.Token) {
			t.Fatal("renewal error handling leaked details or accepted failure")
		}
	}
	if calls != 5 {
		t.Fatal("unexpected request count")
	}
}
func TestTesseraStorageNeverFollowsRedirects(t *testing.T) {
	c := testStorageConnection()
	destinationCalls := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalls++ }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	c.Origin = redirect.URL
	client := tesseraStorageClient()
	client.Transport = redirect.Client().Transport
	if _, err := tesseraConnectionRequest(c, client); err == nil {
		t.Fatal("accepted redirect")
	}
	if destinationCalls != 0 {
		t.Fatal("forwarded token to redirect destination")
	}
}

func TestTesseraConnectionDraftBinding(t *testing.T) {
	c := testStorageConnection()
	d := coordinatorDraft{TesseraSetup: &setupv2.Setup{ID: c.CeremonyID}}
	d.Identities.Coordinator.Fingerprint = c.CoordinatorFingerprint
	d.TesseraSetup.Plan.Storage = setupv2.Storage{Provider: "aws", Region: c.Settings.Settings["region"], PublicBaseURL: c.Settings.Settings["published-base-url"], PublishedBucket: c.Settings.Settings["published-bucket"], InboxBucket: c.Settings.Settings["inbox-bucket"]}
	if err := c.matchesDraft(d); err != nil {
		t.Fatal(err)
	}
	bad := c
	bad.CeremonyID = c.ConnectionID
	if bad.matchesDraft(d) == nil {
		t.Fatal("accepted wrong ceremony")
	}
	bad = c
	bad.CoordinatorFingerprint = "sha256:" + strings.Repeat("f", 64)
	if bad.matchesDraft(d) == nil {
		t.Fatal("accepted wrong signing key")
	}
	d.TesseraSetup.Plan.Storage.InboxBucket = "other"
	if c.matchesDraft(d) == nil {
		t.Fatal("accepted changed storage")
	}
}
