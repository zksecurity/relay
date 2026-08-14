package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hex64 = "1111111111111111111111111111111111111111111111111111111111111111"

func validPointer() Pointer {
	return Pointer{
		Schema:         Schema,
		CeremonyID:     "sha256:" + hex64,
		Phase:          "phase1",
		Index:          3,
		Chain:          Ref{Name: "phase1/chain-0003.json", SHA256: "sha256:" + hex64},
		ChainSignature: Ref{Name: "phase1/chain-0003.sig", SHA256: "sha256:" + hex64},
		UpdatedAt:      "2026-08-14T00:00:00Z",
	}
}

func TestPointerRoundTrip(t *testing.T) {
	encoded, err := validPointer().Encode()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if decoded.Index != 3 || decoded.Phase != "phase1" {
		t.Fatalf("round trip lost fields: %+v", decoded)
	}
}

func TestPointerRejectsMalformed(t *testing.T) {
	cases := map[string]func(*Pointer){
		"wrong schema":     func(p *Pointer) { p.Schema = "something-else" },
		"unknown phase":    func(p *Pointer) { p.Phase = "phase3" },
		"negative index":   func(p *Pointer) { p.Index = -1 },
		"untagged digest":  func(p *Pointer) { p.Chain.SHA256 = hex64 },
		"truncated digest": func(p *Pointer) { p.Chain.SHA256 = "sha256:abcd" },
		"nameless ref":     func(p *Pointer) { p.ChainSignature.Name = "" },
	}
	for label, mutate := range cases {
		p := validPointer()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("Validate accepted a pointer with %s", label)
		}
	}
}

// TestHighWaterRefusesRollback is the reason the high-water mark exists. A
// pointer that claims less progress than we have already seen names a genuine,
// correctly signed older chain, so nothing downstream would catch it. The cost
// is hours of replay against a head the coordinator has moved past.
func TestHighWaterRefusesRollback(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	hw, err := OpenHighWater("sha256:" + hex64)
	if err != nil {
		t.Fatal(err)
	}
	if err := hw.CheckNotBehind("phase1", 0); err != nil {
		t.Fatalf("a fresh machine should accept any index: %v", err)
	}
	if err := hw.Record("phase1", 3); err != nil {
		t.Fatal(err)
	}
	if err := hw.CheckNotBehind("phase1", 3); err != nil {
		t.Errorf("the same index must still be accepted: %v", err)
	}
	if err := hw.CheckNotBehind("phase1", 4); err != nil {
		t.Errorf("a forward index must be accepted: %v", err)
	}
	err = hw.CheckNotBehind("phase1", 2)
	if err == nil {
		t.Fatal("a rollback to index 2 was accepted")
	}
	if !strings.Contains(err.Error(), "backwards") {
		t.Errorf("unhelpful rollback error: %v", err)
	}
}

// TestHighWaterNeverRetreats guards the recording side: a stale pointer must
// not be able to lower the mark and re-enable the rollback it was blocked for.
func TestHighWaterNeverRetreats(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	hw, err := OpenHighWater("sha256:" + hex64)
	if err != nil {
		t.Fatal(err)
	}
	if err := hw.Record("phase1", 5); err != nil {
		t.Fatal(err)
	}
	if err := hw.Record("phase1", 2); err != nil {
		t.Fatal(err)
	}
	seen, err := hw.Seen("phase1")
	if err != nil {
		t.Fatal(err)
	}
	if seen != 5 {
		t.Fatalf("high-water retreated to %d, want 5", seen)
	}
}

func TestHighWaterIsPerPhase(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	hw, err := OpenHighWater("sha256:" + hex64)
	if err != nil {
		t.Fatal(err)
	}
	if err := hw.Record("phase1", 5); err != nil {
		t.Fatal(err)
	}
	// Phase 2 starts from zero; phase 1's progress must not block it.
	if err := hw.CheckNotBehind("phase2", 0); err != nil {
		t.Errorf("phase1 progress leaked into phase2: %v", err)
	}
}

func TestHighWaterIsPerCeremony(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	first, err := OpenHighWater("sha256:" + hex64)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Record("phase1", 5); err != nil {
		t.Fatal(err)
	}
	second, err := OpenHighWater("sha256:" + strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := second.CheckNotBehind("phase1", 0); err != nil {
		t.Errorf("one ceremony's progress blocked another: %v", err)
	}
	// The ceremony id contains a colon; the directory must still be usable.
	entries, err := os.ReadDir(filepath.Join(home, ".mpc-sync"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("expected two ceremony directories, got %v (%v)", entries, err)
	}
}

// TestKeyIsNamespacedByCeremony guards against the collision that made two
// ceremonies in one bucket overwrite each other's pointer. The blobs survive
// either way because they are content-addressed and immutable, but without the
// namespace nothing names the earlier transcript any more.
func TestKeyIsNamespacedByCeremony(t *testing.T) {
	first := Key("sha256:"+hex64, "phase1")
	if first != "state/"+hex64+"/phase1/head.json" {
		t.Errorf("Key = %q", first)
	}
	second := Key("sha256:"+strings.Repeat("2", 64), "phase1")
	if first == second {
		t.Fatal("two ceremonies share one phase1 pointer key")
	}
	if Key("sha256:"+hex64, "phase2") == first {
		t.Fatal("phase1 and phase2 share a pointer key")
	}
}
