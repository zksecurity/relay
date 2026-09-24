package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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

// This opt-in test checks real S3 conditional multipart completion without
// involving a ceremony or creating an approved-release pointer.
func TestLiveConditionalMultipartPublication(t *testing.T) {
	bucket := os.Getenv("RELAY_TEST_PUBLISHED_BUCKET")
	profile := os.Getenv("RELAY_TEST_AWS_PROFILE")
	region := os.Getenv("RELAY_TEST_AWS_REGION")
	if bucket == "" || profile == "" || region == "" {
		t.Skip("set test bucket, AWS profile and region for live conditional multipart validation")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	key := "tests/go-publication-conditional/" + hex.EncodeToString(nonce[:]) + "/archive.bin"
	client := Client{Profile: profile, Region: region, Bucket: bucket}
	defer func() {
		if err := client.Delete(key); err != nil {
			t.Errorf("remove isolated test object %s: %v", key, err)
		}
	}()
	work := t.TempDir()
	source := filepath.Join(work, "public-test-archive.bin")
	f, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte("public test bytes"), 750000)); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	open := func() *os.File {
		t.Helper()
		f, err := os.Open(source)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	first := open()
	err = client.putMultipartNoReplace(first, info.Size(), key, work, 6<<20)
	first.Close()
	if err != nil {
		t.Fatal(err)
	}
	second := open()
	err = client.putMultipartNoReplace(second, info.Size(), key, work, 6<<20)
	second.Close()
	if err == nil {
		t.Fatal("real S3 replaced an existing multipart publication object")
	}
	readback := filepath.Join(work, "readback.bin")
	if err := client.Get(key, readback); err != nil {
		t.Fatal(err)
	}
	expected, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(readback)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(actual) != sha256.Sum256(expected) {
		t.Fatal("real S3 readback differs from the first conditional publication")
	}
}
