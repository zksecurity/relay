package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/state"
)

func TestReleaseSnapshotRejectsWrongBindingAndUnsafeInventory(t *testing.T) {
	id := "sha256:" + strings.Repeat("a", 64)
	checkpoint := "sha256:" + strings.Repeat("b", 64)
	signature := "sha256:" + strings.Repeat("c", 64)
	ref := state.ContentRef{Name: "checkpoints/review.json", SHA256: checkpoint, Size: 100}
	m := workflowV4PublicSnapshot{
		Schema: "relay-public-snapshot-v1",
		Root: state.Root{Schema: state.RootSchema, CeremonyID: id, Checkpoint: ref,
			CheckpointSignature: state.ContentRef{Name: "checkpoints/review.sig", SHA256: signature, Size: 64}},
		Files: []state.ContentRef{ref, {Name: "checkpoints/review.sig", SHA256: signature, Size: 64}},
	}
	if err := workflowV4ValidateReleaseSnapshot(m, id, checkpoint); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*workflowV4PublicSnapshot){
		"wrong ceremony":   func(m *workflowV4PublicSnapshot) { m.Root.CeremonyID = "sha256:" + strings.Repeat("d", 64) },
		"wrong checkpoint": func(m *workflowV4PublicSnapshot) { m.Root.Checkpoint.SHA256 = "sha256:" + strings.Repeat("d", 64) },
		"duplicate name":   func(m *workflowV4PublicSnapshot) { m.Files[1].Name = m.Files[0].Name },
		"traversal":        func(m *workflowV4PublicSnapshot) { m.Files[1].Name = "../secret" },
		"oversize":         func(m *workflowV4PublicSnapshot) { m.Files[1].Size = 16<<30 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := m
			changed.Files = append([]state.ContentRef(nil), m.Files...)
			mutate(&changed)
			if err := workflowV4ValidateReleaseSnapshot(changed, id, checkpoint); err == nil {
				t.Fatal("unsafe or mismatched release snapshot was accepted")
			}
		})
	}
}

func TestSignerDownloadsExactPublicReleaseSnapshot(t *testing.T) {
	work := privateRoleTestDir(t)
	id := "sha256:" + strings.Repeat("a", 64)
	checkpointBytes := []byte("signed review checkpoint")
	signatureBytes := []byte("review checkpoint signature")
	digest := func(raw []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) }
	checkpoint := digest(checkpointBytes)
	signature := digest(signatureBytes)
	manifest := workflowV4PublicSnapshot{
		Schema: "relay-public-snapshot-v1",
		Root: state.Root{Schema: state.RootSchema, CeremonyID: id,
			Checkpoint:          state.ContentRef{Name: "checkpoints/review.json", SHA256: checkpoint, Size: int64(len(checkpointBytes))},
			CheckpointSignature: state.ContentRef{Name: "checkpoints/review.sig", SHA256: signature, Size: int64(len(signatureBytes))}},
		Files: []state.ContentRef{
			{Name: "checkpoints/review.json", SHA256: checkpoint, Size: int64(len(checkpointBytes))},
			{Name: "checkpoints/review.sig", SHA256: signature, Size: int64(len(signatureBytes))},
		},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestSHA := digest(manifestBytes)
	objects := map[string][]byte{
		"/blob/sha256/" + strings.TrimPrefix(manifestSHA, "sha256:"): manifestBytes,
		"/blob/sha256/" + strings.TrimPrefix(checkpoint, "sha256:"):  checkpointBytes,
		"/blob/sha256/" + strings.TrimPrefix(signature, "sha256:"):   signatureBytes,
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw, ok := objects[r.URL.Path]; ok {
			_, _ = w.Write(raw)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	priorClient := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func() { http.DefaultClient = priorClient }()
	input := fmt.Sprintf("%s\n%s\n%s\n%s\n", server.URL, id, checkpoint, manifestSHA)
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader(input)), output: new(bytes.Buffer)}
	if err := workflowV4SignerDownloadReleaseSnapshot(ui, work); err != nil {
		t.Fatal(err)
	}
	downloads, err := filepath.Glob(filepath.Join(work, "incoming-release-*"))
	if err != nil || len(downloads) != 1 {
		t.Fatalf("expected one complete release snapshot, got %v: %v", downloads, err)
	}
	if _, err := openWorkflowV4OfflineStore(downloads[0]); err != nil {
		t.Fatal(err)
	}
	objects["/blob/sha256/"+strings.TrimPrefix(checkpoint, "sha256:")] = []byte("altered bytes")
	ui.input = bufio.NewReader(strings.NewReader(input))
	if err := workflowV4SignerDownloadReleaseSnapshot(ui, work); err == nil {
		t.Fatal("altered public object was accepted")
	}
	downloads, err = filepath.Glob(filepath.Join(work, "incoming-release-*"))
	if err != nil || len(downloads) != 1 {
		t.Fatalf("failed download left a partial snapshot: %v: %v", downloads, err)
	}
	if _, err := os.Stat(filepath.Join(downloads[0], offlineSnapshotFile)); err != nil {
		t.Fatal(err)
	}
}

func TestSignerOnlineTransferWaitsForOfflineGuideExit(t *testing.T) {
	work := privateRoleTestDir(t)
	guideLock, err := acquireParticipantRunLock("", work)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := workflowV4WithSignerTransferLock(work, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("online transfer started while the offline guide held the workspace")
	}
	if err := guideLock.release(); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4WithSignerTransferLock(work, func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("online transfer did not start after guide exit: %v", err)
	}
}
