package store

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installConditionalAWS(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	executable := filepath.Join(dir, "aws")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"+script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func TestGetVersionedAtMostPinsExactProviderVersion(t *testing.T) {
	dir := installConditionalAWS(t, `
printf '%s\n' "$*" >> "$RELAY_TEST_CALLS"
case " $* " in
  *" head-object "*) printf '%s\n' '{"ETag":"\"root-v1\"","VersionId":"version-1","ContentLength":4}' ;;
  *" get-object "*)
    for destination do :; done
    printf root > "$destination"
    printf '%s\n' '{"ETag":"\"root-v1\"","VersionId":"version-1"}'
    ;;
esac
`)
	calls := filepath.Join(dir, "calls")
	t.Setenv("RELAY_TEST_CALLS", calls)
	out := filepath.Join(dir, "root.json")
	version, err := (Client{Bucket: "published"}).GetVersionedAtMost("state/id/root.json", out, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if version.ETag != `"root-v1"` || version.VersionID != "version-1" || version.Size != 4 {
		t.Fatalf("version = %#v", version)
	}
	raw, err := os.ReadFile(out)
	if err != nil || string(raw) != "root" {
		t.Fatalf("download = %q (%v)", raw, err)
	}
	log, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	text := string(log)
	if !strings.Contains(text, `--if-match "root-v1"`) || !strings.Contains(text, "--version-id version-1") {
		t.Fatalf("download was not pinned to the HEAD result: %s", text)
	}
}

func TestGetVersionedAtMostRejectsOversizeBeforeDownload(t *testing.T) {
	dir := installConditionalAWS(t, `
printf '%s\n' "$*" >> "$RELAY_TEST_CALLS"
printf '%s\n' '{"ETag":"\"large\"","ContentLength":1025}'
`)
	calls := filepath.Join(dir, "calls")
	t.Setenv("RELAY_TEST_CALLS", calls)
	out := filepath.Join(dir, "root.json")
	if _, err := (Client{Bucket: "published"}).GetVersionedAtMost("state/id/root.json", out, 1024); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %v", err)
	}
	log, _ := os.ReadFile(calls)
	if strings.Contains(string(log), "get-object") {
		t.Fatalf("oversize object was downloaded: %s", log)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize download left output: %v", err)
	}
}

func TestGetVersionedAtMostMapsReadRaceToConflict(t *testing.T) {
	dir := installConditionalAWS(t, `
case " $* " in
  *" head-object "*) printf '%s\n' '{"ETag":"\"old\"","ContentLength":4}' ;;
  *) printf '%s\n' 'PreconditionFailed: status code: 412' >&2; exit 1 ;;
esac
`)
	out := filepath.Join(dir, "root.json")
	_, err := (Client{Bucket: "published"}).GetVersionedAtMost("state/id/root.json", out, 1024)
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("read race error = %v", err)
	}
	if _, statErr := os.Lstat(out); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed read left output: %v", statErr)
	}
}

func TestConditionalWritesUseDistinctConflictErrors(t *testing.T) {
	dir := installConditionalAWS(t, `
printf '%s\n' "$*" >> "$RELAY_TEST_CALLS"
printf '%s\n' 'PreconditionFailed: status code: 412' >&2
exit 1
`)
	calls := filepath.Join(dir, "calls")
	t.Setenv("RELAY_TEST_CALLS", calls)
	local := filepath.Join(dir, "new-root")
	if err := os.WriteFile(local, []byte("root"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := Client{Bucket: "published"}
	if _, err := client.PutIfAbsent("state/id/root.json", local); !errors.Is(err, ErrExists) || errors.Is(err, ErrVersionConflict) {
		t.Fatalf("create conflict = %v", err)
	}
	if _, err := client.PutIfMatch("state/id/root.json", local, ObjectVersion{ETag: `"old"`, Size: 4}); !errors.Is(err, ErrVersionConflict) || errors.Is(err, ErrExists) {
		t.Fatalf("replace conflict = %v", err)
	}
	log, _ := os.ReadFile(calls)
	if !strings.Contains(string(log), "--if-none-match *") || !strings.Contains(string(log), `--if-match "old"`) {
		t.Fatalf("conditional flags missing: %s", log)
	}
}

func TestConditionalWriteDoesNotConvertUnrelatedFailure(t *testing.T) {
	dir := installConditionalAWS(t, `
printf '%s\n' 'connection reset' >&2
exit 1
`)
	local := filepath.Join(dir, "new-root")
	if err := os.WriteFile(local, []byte("root"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := (Client{Bucket: "published"}).PutIfAbsent("state/id/root.json", local)
	if err == nil || errors.Is(err, ErrExists) || errors.Is(err, ErrVersionConflict) {
		t.Fatalf("unrelated failure was misclassified: %v", err)
	}
}

func TestConditionalWriteReturnsNewVersion(t *testing.T) {
	dir := installConditionalAWS(t, `
printf '%s\n' '{"ETag":"\"new\"","VersionId":"version-2"}'
`)
	local := filepath.Join(dir, "new-root")
	if err := os.WriteFile(local, []byte("root"), 0o600); err != nil {
		t.Fatal(err)
	}
	version, err := (Client{Bucket: "published"}).PutIfMatch("state/id/root.json", local, ObjectVersion{ETag: `"old"`, Size: 3})
	if err != nil {
		t.Fatal(err)
	}
	if version.ETag != `"new"` || version.VersionID != "version-2" || version.Size != 4 {
		t.Fatalf("new version = %#v", version)
	}
}

func TestPublicVersionedReadIsStreamBounded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"public"`)
		_, _ = w.Write([]byte("12345"))
	}))
	defer server.Close()
	dir := t.TempDir()
	out := filepath.Join(dir, "root.json")
	client := Client{PublicBaseURL: server.URL, httpClient: server.Client()}
	if _, err := client.GetVersionedAtMost("state/id/root.json", out, 4); err == nil {
		t.Fatal("oversize public response was accepted")
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversize public response left output: %v", err)
	}
}

func TestPublicVersionedReadRefusesCrossOriginRedirect(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("root"))
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/root", http.StatusFound)
	}))
	defer source.Close()
	dir := t.TempDir()
	client := Client{PublicBaseURL: source.URL, httpClient: source.Client()}
	if _, err := client.GetVersionedAtMost("state/id/root.json", filepath.Join(dir, "root.json"), 1024); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("cross-origin redirect error = %v", err)
	}
}
