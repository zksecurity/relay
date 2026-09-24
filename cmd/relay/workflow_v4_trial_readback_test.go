package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zksecurity/relay/internal/store"
)

func TestWorkflowV4TrialReadbackDownloadsIntoFreshPath(t *testing.T) {
	body := []byte("signed trial archive bytes")
	digest := sha256.Sum256(body)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/trials/no-go/test/ceremony.zip" {
			t.Errorf("unexpected readback path %s", r.URL.Path)
		}
		_, _ = w.Write(body)
	}))
	defer server.Close()
	previous := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = previous }()
	public := store.Client{PublicBaseURL: server.URL}
	if err := checkWorkflowV4TrialReadback(public, "trials/no-go/test/ceremony.zip", hex.EncodeToString(digest[:]), t.TempDir()); err != nil {
		t.Fatal(err)
	}
}
