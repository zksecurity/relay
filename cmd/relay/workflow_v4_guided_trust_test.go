package main

import (
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowV4ReleaseVerifierUsesRoleTrustFile(t *testing.T) {
	for _, tc := range []struct {
		role string
		want string
	}{
		{"coordinator", "/trust/setup-coordinator.hex"},
		{"release-signer", "/trust/coordinator-public-key.hex"},
		{"upload-station", "/trust/coordinator-public-key.hex"},
	} {
		t.Run(tc.role, func(t *testing.T) {
			work, trust := t.TempDir(), t.TempDir()
			profile := guidedProfile{Role: tc.role, Work: work, Trust: trust, ReleaseCommit: strings.Repeat("a", 40), Image: "example.test/online@sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64"}
			previous := workflowV4ChildExecutor
			defer func() { workflowV4ChildExecutor = previous }()
			var launch []string
			workflowV4ChildExecutor = func(args []string) error { launch = append([]string(nil), args...); return nil }
			if err := runWorkflowV4VerifyReleasePackage(profile, filepath.Join(work, "ceremony", "public", "final", "release"), "release-key"); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(launch, " "), "--coordinator-public-key-file "+tc.want) {
				t.Fatalf("%s used wrong trust file: %v", tc.role, launch)
			}
		})
	}
}

func TestWorkflowV4CoordinatorKeyComparisonAcceptsFinalNewlineOnly(t *testing.T) {
	key := hex.EncodeToString([]byte(strings.Repeat("k", 32)))
	if !sameCoordinatorPublicKey([]byte(key), []byte(key+"\n")) {
		t.Fatal("same key with final newline rejected")
	}
	other := hex.EncodeToString([]byte(strings.Repeat("x", 32)))
	if sameCoordinatorPublicKey([]byte(key), []byte(other)) || sameCoordinatorPublicKey([]byte(key), []byte(key+"x")) {
		t.Fatal("changed or malformed key accepted")
	}
}
