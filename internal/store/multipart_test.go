package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMultipartPublicationCompletesOnlyWithNoReplace(t *testing.T) {
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	shim := `#!/bin/sh
printf '%s\n' "$*" >> "$AWS_TEST_LOG"
case "$*" in
  *create-multipart-upload*) printf '{"UploadId":"test-upload"}\n' ;;
  *upload-part*) printf '{"ETag":"test-etag"}\n' ;;
  *complete-multipart-upload*)
    case "$*" in *"--if-none-match *"*) printf '{}\n' ;; *) exit 27 ;; esac ;;
  *abort-multipart-upload*) printf '{}\n' ;;
  *) exit 28 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AWS_TEST_LOG", log)
	source := filepath.Join(t.TempDir(), "archive.zip")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(11 << 20); err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	client := Client{Bucket: "published"}
	if err := client.putMultipartNoReplace(file, 11<<20, "approved/one/archive.zip", t.TempDir(), 6<<20); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(raw)
	if strings.Count(calls, "upload-part") != 2 || !strings.Contains(calls, "complete-multipart-upload") || !strings.Contains(calls, "--if-none-match *") || strings.Contains(calls, "abort-multipart-upload") {
		t.Fatalf("unsafe multipart command sequence: %s", calls)
	}
}
