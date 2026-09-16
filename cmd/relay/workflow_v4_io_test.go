package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowV4PrivateStrictRead(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"duplicate", `{"value":"a","value":"b"}`},
		{"unknown", `{"other":"a"}`},
		{"trailing", `{"value":"a"} {}`},
		{"malformed", `{"value":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			var state struct {
				Value string `json:"value"`
			}
			if err := readWorkflowV4JSON(path, &state); err == nil {
				t.Fatal("accepted invalid state")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "state.json")
	want := struct {
		Value string `json:"value"`
	}{strings.Repeat("x", 2<<20)}
	if err := saveJSONAtomicWithLimit(path, want, workflowV4MaximumBytes); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Value string `json:"value"`
	}
	if err := readWorkflowV4JSON(path, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("round trip changed state")
	}
	if err := saveJSONAtomic(path, want); err == nil {
		t.Fatal("legacy size limit changed")
	}
	if err := saveJSONAtomicWithLimit(path, want, 0); err == nil {
		t.Fatal("accepted invalid bound")
	}
	if err := readWorkflowV4JSON(path, &got); err != nil || got != want {
		t.Fatal("failed save replaced old state", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := readWorkflowV4JSON(link, &got); err == nil {
		t.Fatal("accepted symlink")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := readWorkflowV4JSON(path, &got); err == nil {
		t.Fatal("accepted public state")
	}
}
