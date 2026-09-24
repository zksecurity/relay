package store

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicDownloadRejectsBytesBeyondApprovedSize(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("published object is longer"))
	}))
	defer server.Close()
	previous := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = previous }()
	path := filepath.Join(t.TempDir(), "object")
	if err := (Client{PublicBaseURL: server.URL}).GetPublicAtMost("approved/object", path, 4); err == nil {
		t.Fatal("oversized public object accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("oversized partial download was retained")
	}
}

func TestBoundedOfficialDownloadRejectsRedirect(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://another.example/approved/release.json", http.StatusFound)
	}))
	defer server.Close()
	previous := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = previous }()
	path := filepath.Join(t.TempDir(), "release.json")
	if err := (Client{PublicBaseURL: server.URL}).GetPublicAtMost("approved/release.json", path, 4096); err == nil {
		t.Fatal("official object redirect was accepted")
	}
}
