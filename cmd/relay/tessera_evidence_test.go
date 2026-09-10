package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type evidenceRoundTrip func(*http.Request) (*http.Response, error)

func (f evidenceRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRoleConnectionStrictPrivateFileAndAuthenticatedRequest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connection.json")
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	raw := `{"schema":"tessera-role-connection-v1","connection_id":"11111111-1111-4111-8111-111111111111","ceremony_id":"22222222-2222-4222-8222-222222222222","protocol_id":"sha256:` + strings.Repeat("a", 64) + `","assignment_id":"33333333-3333-4333-8333-333333333333","origin":"https://tessera.example","expires_at":"` + future + `","role":"participant","identity_id":"participant-01","token":"` + strings.Repeat("x", 43) + `"}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	connection, err := loadTesseraRoleConnection(path)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: evidenceRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.URL.String() != "https://tessera.example/api/v1/cli-evidence/11111111-1111-4111-8111-111111111111/submissions" {
			t.Fatalf("url %s", request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer "+strings.Repeat("x", 43) {
			t.Fatal("missing bearer")
		}
		body, _ := io.ReadAll(request.Body)
		if !bytes.Contains(body, []byte(`"manifest_key":"safe/key/manifest.json"`)) {
			t.Fatalf("body %s", body)
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader(`{"data":{"submission":{}}}`)), Header: make(http.Header)}, nil
	})}
	var result struct {
		Submission map[string]any `json:"submission"`
	}
	if err = tesseraRoleRequestWithClient(connection, "submissions", map[string]any{"manifest_key": "safe/key/manifest.json"}, &result, client); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadTesseraRoleConnection(path); err == nil {
		t.Fatal("public connection file accepted")
	}
}
