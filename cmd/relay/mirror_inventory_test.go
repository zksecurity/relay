package main

import (
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/transcript"
	"strings"
	"testing"
)

func mirrorPosition() position {
	sha := "sha256:" + strings.Repeat("a", 64)
	p := position{definition: transcript.Definition{R1CSRef: transcript.ArtifactRef{Name: "ownership-destination.ccs", Digest: transcript.Digest{SHA256: sha, Size: 100}}}, chain: transcript.Chain{Phase: "phase1"}}
	p.pointer.Chain = state.Ref{Name: "phase1/chain-0000.json", SHA256: sha}
	p.pointer.ChainSignature = state.Ref{Name: "phase1/chain-0000.sig", SHA256: sha}
	for _, name := range []string{"ceremony.json", "ceremony.sig", "ownership-destination.ccs", "phase1/closure/record.json", "phase1/closure/record.sig"} {
		p.pointer.Files = append(p.pointer.Files, state.Ref{Name: name, SHA256: sha})
	}
	return p
}
func TestMirrorDiscoversRemoteClosureAndUsesSignedCircuitDigest(t *testing.T) {
	p := mirrorPosition()
	files, err := mirrorSyncFiles(p)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range files {
		if f.Name == "phase1/closure/record.json" {
			found = true
		}
		if f.Name == "ownership-destination.ccs" && f.Digest.Size != 100 {
			t.Fatal("signed circuit size lost")
		}
	}
	if !found {
		t.Fatal("remote closure not discovered")
	}
}
func TestMirrorRejectsConflictsAndMissingHistoricalPrefixes(t *testing.T) {
	p := mirrorPosition()
	p.pointer.Files[2].SHA256 = "sha256:" + strings.Repeat("b", 64)
	if _, err := mirrorSyncFiles(p); err == nil {
		t.Fatal("inventory overrode signed circuit")
	}
	p = mirrorPosition()
	p.accepted = 1
	if _, err := mirrorSyncFiles(p); err == nil {
		t.Fatal("missing historical prefix accepted")
	}
}
func TestMirrorRejectsPrivatePathsAndDuplicateNames(t *testing.T) {
	for _, name := range []string{"../signing.hex", "keys/signing.hex", "ceremony.json"} {
		p := mirrorPosition()
		p.pointer.Files = append(p.pointer.Files, state.Ref{Name: name, SHA256: p.pointer.Chain.SHA256})
		if _, err := mirrorSyncFiles(p); err == nil {
			t.Fatal("invalid inventory accepted")
		}
	}
}
