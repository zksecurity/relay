package store

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func shortPublicIdle(t *testing.T) {
	t.Helper()
	old := publicReadTimeout
	publicReadTimeout = 150 * time.Millisecond
	t.Cleanup(func() { publicReadTimeout = old })
}

func TestLargePublicDownloadContinuesWhileProgressing(t *testing.T) {
	shortPublicIdle(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 8; i++ {
			if _, err := w.Write([]byte("data")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-time.After(35 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "artifact")
	start := time.Now()
	version, err := (Client{PublicBaseURL: server.URL, httpClient: server.Client()}).GetVersionedAtMost("blob/artifact", output, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	if version.Size != 32 || time.Since(start) <= publicReadTimeout {
		t.Fatalf("did not exercise progressing long read: %+v", version)
	}
}

func TestLargePublicDownloadCancelsStalls(t *testing.T) {
	for _, kind := range []string{"headers", "body", "partial", "error-body"} {
		t.Run(kind, func(t *testing.T) {
			shortPublicIdle(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if kind != "headers" {
					if kind == "error-body" {
						w.WriteHeader(http.StatusBadGateway)
					} else {
						w.WriteHeader(http.StatusOK)
					}
					if kind == "partial" {
						_, _ = w.Write([]byte("partial"))
					}
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			output := filepath.Join(t.TempDir(), "artifact")
			start := time.Now()
			_, err := (Client{PublicBaseURL: server.URL, httpClient: server.Client()}).GetVersionedAtMost("blob/artifact", output, 16<<30)
			if err == nil {
				t.Fatal("stall succeeded")
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("stall ignored inactivity limit")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("partial file retained: %v", err)
			}
		})
	}
}

func TestPublicDownloadParentCancellationRemovesPartial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("partial"))
		w.(http.Flusher).Flush()
		cancel()
		<-r.Context().Done()
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "artifact")
	_, err := (Client{PublicBaseURL: server.URL, httpClient: server.Client()}).WithContext(ctx).GetVersionedAtMost("blob/artifact", output, 2<<20)
	if err == nil {
		t.Fatal("cancelled download succeeded")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("partial file retained: %v", err)
	}
}

func TestPublicDownloadChunkedOverflowRemovesPartial(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("too large"))
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "artifact")
	_, err := (Client{PublicBaseURL: server.URL, httpClient: server.Client()}).GetVersionedAtMost("blob/artifact", output, 3)
	if err == nil {
		t.Fatal("chunked overflow succeeded")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("partial file retained: %v", err)
	}
}

func TestPublicDownloadProgressCannotExtendTotalBudget(t *testing.T) {
	shortPublicIdle(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			w.(http.Flusher).Flush()
			select {
			case <-time.After(35 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
	}))
	defer server.Close()
	output := filepath.Join(t.TempDir(), "artifact")
	start := time.Now()
	_, err := (Client{PublicBaseURL: server.URL, httpClient: server.Client()}).GetVersionedAtMost("blob/artifact", output, (1<<20)+1)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("endless progressing download succeeded")
	}
	if elapsed < time.Second || elapsed > 4*time.Second {
		t.Fatalf("unexpected total deadline: %s", elapsed)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("partial file retained: %v", err)
	}
}
