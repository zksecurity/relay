package teststore

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestConditionalStorage(t *testing.T) {
	s := New()
	s.Endpoint = "https://local.test"
	s.CoordinatorKey = "key"
	s.CoordinatorSecret = "secret"
	call := func(op string, extra ...string) Response {
		args := []string{"--endpoint-url", s.Endpoint, "s3api", op, "--bucket", "published", "--key", "a"}
		args = append(args, extra...)
		return s.Execute(Request{Args: args, Key: "key", Secret: "secret", Body: []byte("payload")})
	}
	a := call("put-object", "--if-none-match", "*")
	if a.Error != "" {
		t.Fatal(a.Error)
	}
	if b := call("put-object", "--if-none-match", "*"); b.Error != "PreconditionFailed" {
		t.Fatal(b)
	}
	var meta struct{ ETag, VersionId string }
	if e := json.Unmarshal(a.Output, &meta); e != nil {
		t.Fatal(e)
	}
	if b := call("put-object", "--if-match", "stale"); b.Error != "PreconditionFailed" {
		t.Fatal(b)
	}
	b := call("put-object", "--if-match", meta.ETag)
	if b.Error != "" {
		t.Fatal(b.Error)
	}
	if b := call("get-object", "--version-id", meta.VersionId); b.Error != "PreconditionFailed" {
		t.Fatal(b)
	}
	if b := call("get-object", "--range", "bytes=0-2"); string(b.Body) != "pay" {
		t.Fatal(b)
	}
	if b := call("unknown"); b.Error != "UnsupportedOperation" {
		t.Fatal(b)
	}
	if b := call("get-object", "--key", "../a"); b.Error != "InvalidKey" {
		t.Fatal(b)
	}
	if b := call("get-object", "--no-sign-request"); b.Error != "AccessDenied" {
		t.Fatal(b)
	}
}
func TestPaginationAndConcurrentCreate(t *testing.T) {
	s := New()
	s.Endpoint = "https://local.test"
	s.CoordinatorKey = "k"
	s.CoordinatorSecret = "s"
	call := func(op, key string, extra ...string) Response {
		return s.Execute(Request{Args: append([]string{"--endpoint-url", s.Endpoint, "s3api", op, "--bucket", "published", "--key", key}, extra...), Key: "k", Secret: "s"})
	}
	for i := 0; i < 101; i++ {
		if r := call("put-object", fmt.Sprintf("prefix/%03d", i), "--if-none-match", "*"); r.Error != "" {
			t.Fatal(r.Error)
		}
	}
	r := call("list-objects-v2", "", "--prefix", "prefix/")
	var page struct {
		Contents              []any
		IsTruncated           bool
		NextContinuationToken string
	}
	json.Unmarshal(r.Output, &page)
	if len(page.Contents) != 100 || !page.IsTruncated {
		t.Fatal(string(r.Output))
	}
	r = call("list-objects-v2", "", "--prefix", "prefix/", "--continuation-token", page.NextContinuationToken)
	json.Unmarshal(r.Output, &page)
	if len(page.Contents) != 1 || page.IsTruncated {
		t.Fatal(string(r.Output))
	}
	done := make(chan Response, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- call("put-object", "race", "--if-none-match", "*") }()
	}
	success := 0
	for i := 0; i < 2; i++ {
		if (<-done).Error == "" {
			success++
		}
	}
	if success != 1 {
		t.Fatal("create-only was not atomic")
	}
}
