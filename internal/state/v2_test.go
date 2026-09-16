package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func digestOf(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func validRoot() Root {
	return Root{
		Schema:              RootSchema,
		CeremonyID:          digestOf("1"),
		Checkpoint:          ContentRef{Name: "checkpoints/0003.json", SHA256: digestOf("2"), Size: 1200},
		CheckpointSignature: ContentRef{Name: "checkpoints/0003.sig", SHA256: digestOf("3"), Size: 300},
	}
}

func TestWorkspaceHighWaterConcurrentStaleWriterCannotOverwriteNewerPosition(t *testing.T) {
	highWater := openWorkspaceHighWater(t)
	cp1 := checkpoint(1, digestOf("1"), digestOf("0"), 0)
	if err := highWater.Record(cp1); err != nil {
		t.Fatal(err)
	}
	cp2 := checkpoint(2, digestOf("2"), cp1.Digest, 1)
	cp3 := checkpoint(3, digestOf("3"), cp2.Digest, 1)

	// This writer computed cp2 from the same older workspace view, then pauses
	// immediately before entering the transaction lock. A second sync advances
	// through cp2 to cp3 first. When released, the stale writer must re-read cp3
	// while holding the lock and reject its cp2 instead of overwriting cp3.
	stale := highWater
	staleReady := make(chan struct{})
	releaseStale := make(chan struct{})
	stale.lock = func(path string) (func(), error) {
		close(staleReady)
		<-releaseStale
		return lockWorkspaceHighWater(path)
	}
	staleResult := make(chan error, 1)
	go func() { staleResult <- stale.Record(cp2) }()

	select {
	case <-staleReady:
	case <-time.After(5 * time.Second):
		t.Fatal("stale writer did not reach the deterministic race boundary")
	}
	if err := highWater.Record(cp2); err != nil {
		t.Fatal(err)
	}
	if err := highWater.Record(cp3); err != nil {
		t.Fatal(err)
	}
	close(releaseStale)
	select {
	case err := <-staleResult:
		if err == nil || !strings.Contains(err.Error(), "moved backwards") {
			t.Fatalf("stale cp2 result = %v, want rollback rejection", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale writer did not finish")
	}
	seen, exists, err := highWater.Seen()
	if err != nil || !exists {
		t.Fatalf("Seen = %+v, %v, %v", seen, exists, err)
	}
	if !reflect.DeepEqual(seen, cp3) {
		t.Fatalf("stale writer replaced cp3: got %+v, want %+v", seen, cp3)
	}
}

func TestRootRoundTripAndKey(t *testing.T) {
	raw, err := validRoot().Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRoot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Checkpoint.SHA256 != digestOf("2") {
		t.Fatalf("checkpoint digest = %q", got.Checkpoint.SHA256)
	}
	if key := RootKey(got.CeremonyID); key != "state/"+strings.Repeat("1", 64)+"/root.json" {
		t.Fatalf("RootKey = %q", key)
	}
}

func TestRootRejectsMalformedOrUnsafeValues(t *testing.T) {
	cases := map[string]func(*Root){
		"schema":            func(r *Root) { r.Schema = "relay-state-v1" },
		"ceremony":          func(r *Root) { r.CeremonyID = "sha256:ABC" },
		"checkpoint digest": func(r *Root) { r.Checkpoint.SHA256 = digestOf("g") },
		"absolute name":     func(r *Root) { r.Checkpoint.Name = "/checkpoint.json" },
		"traversal":         func(r *Root) { r.CheckpointSignature.Name = "../checkpoint.sig" },
		"zero size":         func(r *Root) { r.Checkpoint.Size = 0 },
		"oversized":         func(r *Root) { r.Checkpoint.Size = 16<<20 + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := validRoot()
			mutate(&root)
			if err := root.Validate(); err == nil {
				t.Fatal("malformed root accepted")
			}
		})
	}
	raw, _ := json.Marshal(validRoot())
	raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
	if _, err := DecodeRoot(raw); err == nil {
		t.Fatal("unknown root field accepted")
	}
	duplicate := []byte(`{"schema":"relay-state-root-v2","schema":"relay-state-root-v2"}`)
	if _, err := DecodeRoot(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate root field was not explicitly rejected: %v", err)
	}
}

func checkpoint(sequence uint64, digest, previous string, index uint64) CheckpointPosition {
	return CheckpointPosition{
		Sequence:       sequence,
		Digest:         digest,
		PreviousDigest: previous,
		PhaseHeads: map[string]PhaseHeadPosition{
			"phase1": {Index: index, Digest: digestOf("a")},
		},
	}
}

func openWorkspaceHighWater(t *testing.T) WorkspaceHighWater {
	t.Helper()
	highWater, err := OpenWorkspaceHighWater(t.TempDir(), digestOf("1"))
	if err != nil {
		t.Fatal(err)
	}
	return highWater
}

func TestWorkspaceHighWaterRecordsForwardAncestryDurably(t *testing.T) {
	highWater := openWorkspaceHighWater(t)
	first := checkpoint(7, digestOf("7"), digestOf("6"), 2)
	if err := highWater.Record(first); err != nil {
		t.Fatal(err)
	}
	second := checkpoint(8, digestOf("8"), first.Digest, 3)
	second.PhaseHeads["phase1"] = PhaseHeadPosition{Index: 3, Digest: digestOf("b")}
	if err := highWater.Record(second); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenWorkspaceHighWater(filepath.Dir(filepath.Dir(filepath.Dir(highWater.path))), digestOf("1"))
	if err != nil {
		t.Fatal(err)
	}
	seen, exists, err := reopened.Seen()
	if err != nil || !exists {
		t.Fatalf("Seen = %+v, %v, %v", seen, exists, err)
	}
	if seen.Sequence != 8 || seen.Digest != digestOf("8") {
		t.Fatalf("durable position = %+v", seen)
	}
	info, err := os.Stat(highWater.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestWorkspaceHighWaterRejectsRollbackForkGapAndWrongParent(t *testing.T) {
	highWater := openWorkspaceHighWater(t)
	first := checkpoint(4, digestOf("4"), digestOf("3"), 2)
	if err := highWater.Record(first); err != nil {
		t.Fatal(err)
	}
	cases := map[string]CheckpointPosition{
		"rollback":  checkpoint(3, digestOf("3"), digestOf("2"), 1),
		"same fork": checkpoint(4, digestOf("5"), digestOf("3"), 2),
		"same digest different state": func() CheckpointPosition {
			p := first
			p.PhaseHeads = map[string]PhaseHeadPosition{"phase1": {Index: 3, Digest: digestOf("8")}}
			return p
		}(),
		"ancestry gap": checkpoint(6, digestOf("6"), first.Digest, 3),
		"wrong parent": checkpoint(5, digestOf("5"), digestOf("9"), 3),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := highWater.Check(candidate); err == nil {
				t.Fatal("unsafe checkpoint accepted")
			}
		})
	}
	seen, _, err := highWater.Seen()
	if err != nil {
		t.Fatal(err)
	}
	if seen.Digest != first.Digest {
		t.Fatalf("rejected checks changed high-water to %+v", seen)
	}
}

func TestWorkspaceHighWaterRejectsPhaseHeadRetreatAndFork(t *testing.T) {
	highWater := openWorkspaceHighWater(t)
	first := checkpoint(4, digestOf("4"), digestOf("3"), 2)
	first.PhaseHeads["phase1"] = PhaseHeadPosition{Index: 2, Digest: digestOf("a"), Closed: true}
	if err := highWater.Record(first); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(*CheckpointPosition){
		"missing": func(p *CheckpointPosition) { delete(p.PhaseHeads, "phase1") },
		"index rollback": func(p *CheckpointPosition) {
			p.PhaseHeads["phase1"] = PhaseHeadPosition{Index: 1, Digest: digestOf("a"), Closed: true}
		},
		"same-index fork": func(p *CheckpointPosition) {
			p.PhaseHeads["phase1"] = PhaseHeadPosition{Index: 2, Digest: digestOf("b"), Closed: true}
		},
		"reopened": func(p *CheckpointPosition) {
			p.PhaseHeads["phase1"] = PhaseHeadPosition{Index: 2, Digest: digestOf("a")}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := checkpoint(5, digestOf("5"), first.Digest, 2)
			candidate.PhaseHeads["phase1"] = first.PhaseHeads["phase1"]
			mutate(&candidate)
			if err := highWater.Check(candidate); err == nil {
				t.Fatal("phase-head retreat/fork accepted")
			}
		})
	}
}

func TestWorkspaceHighWaterRejectsTerminalRetreatOrReplacement(t *testing.T) {
	highWater := openWorkspaceHighWater(t)
	first := checkpoint(9, digestOf("9"), digestOf("8"), 2)
	first.Terminal = &TerminalPosition{Outcome: "go", Digest: digestOf("d")}
	if err := highWater.Record(first); err != nil {
		t.Fatal(err)
	}

	missing := checkpoint(10, digestOf("a"), first.Digest, 2)
	if err := highWater.Check(missing); err == nil {
		t.Fatal("terminal decision was allowed to disappear")
	}
	replaced := missing
	replaced.Terminal = &TerminalPosition{Outcome: "no-go", Digest: digestOf("e")}
	if err := highWater.Check(replaced); err == nil {
		t.Fatal("terminal decision replacement accepted")
	}
	publication := missing
	publication.Terminal = &TerminalPosition{Outcome: "go", Digest: digestOf("d")}
	if err := highWater.Record(publication); err != nil {
		t.Fatalf("checkpoint retaining the terminal decision was rejected: %v", err)
	}
}

func TestWorkspaceHighWaterIsScopedAndRejectsCorruption(t *testing.T) {
	root := t.TempDir()
	firstWorkspace := filepath.Join(root, "participant-1")
	secondWorkspace := filepath.Join(root, "participant-2")
	if err := os.MkdirAll(firstWorkspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(secondWorkspace, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := OpenWorkspaceHighWater(firstWorkspace, digestOf("1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenWorkspaceHighWater(secondWorkspace, digestOf("1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Record(checkpoint(2, digestOf("2"), digestOf("1"), 1)); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := second.Seen(); err != nil || exists {
		t.Fatalf("another workspace observed the first one's mark: exists=%v err=%v", exists, err)
	}
	if err := os.WriteFile(first.path, []byte(`{"schema":"broken"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.Seen(); err == nil {
		t.Fatal("corrupt high-water state was treated as absent")
	}
}
