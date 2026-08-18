package transcript

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateNameRejectsEscapes is the test that matters most here. An
// artifact name comes from a chain document, and on the pull side it is joined
// to a local root to decide where a downloaded file lands. A name that escapes
// the root writes outside the transcript.
func TestValidateNameRejectsEscapes(t *testing.T) {
	for _, name := range []string{
		"",
		".",
		"..",
		"../etc/passwd",
		"phase1/../../etc/passwd",
		"/etc/passwd",
		`phase1\genesis.bin`,
		"phase1//genesis.bin",
		"phase1/./genesis.bin",
		"phase1/../phase2/genesis.bin",
		strings.Repeat("a", 513),
	} {
		if err := ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) accepted an unsafe name", name)
		}
	}
}

func TestValidateNameAcceptsRealArtifacts(t *testing.T) {
	for _, name := range []string{
		"ceremony.json",
		"phase1/genesis.bin",
		"phase1/chain-0003.json",
		"phase1/contributions/0001/contribution.bin",
		"phase2/beacon/raw-response.bin",
	} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) rejected a real artifact: %v", name, err)
		}
	}
}

// TestResolveStaysInsideRoot covers the second half of the same defence: even
// a name that passes validation must not resolve outside the root.
func TestResolveStaysInsideRoot(t *testing.T) {
	root := t.TempDir()
	full, err := Resolve(root, "phase1/genesis.bin")
	if err != nil {
		t.Fatalf("Resolve rejected a valid name: %v", err)
	}
	if !strings.HasPrefix(full, root) {
		t.Fatalf("Resolve returned %q, outside root %q", full, root)
	}
	if _, err := Resolve(root, "../escape"); err == nil {
		t.Fatal("Resolve accepted a name escaping the root")
	}
}

// TestCheckPublishableRefusesNonArtifacts is the guard that keeps private
// material out of a bucket. It must fail closed: anything the ceremony does not
// publish is refused, including things that look plausible.
func TestCheckPublishableRefusesNonArtifacts(t *testing.T) {
	for _, name := range []string{
		"coordinator.ed25519.private.hex",
		"keys/participant-01.ed25519.private.hex",
		"config/participants.json",
		"phase1/contributions/0001/notes.txt",
		"phase1/chain-3.json",     // index not zero padded
		"phase3/genesis.bin",      // no such phase
		"phase2/sealed/seal.json", // phase 2 has no seal document
		"ceremony.json.bak",
	} {
		if err := CheckPublishable(name); err == nil {
			t.Errorf("CheckPublishable(%q) allowed a non-publishable file", name)
		}
	}
}

func TestCheckPublishableAllowsTranscript(t *testing.T) {
	for _, name := range []string{
		"ceremony.json",
		"ceremony.sig",
		"coordinator-public-key.hex",
		"ownership-destination.ccs",
		"phase1/genesis.bin",
		"phase1/chain-0000.json",
		"phase1/chain-0012.sig",
		"phase1/contributions/0001/contribution.bin",
		"phase1/contributions/0020/verification.json",
		"phase1/closure/record.json",
		"phase1/beacon/raw-response.bin",
		"phase1/sealed/commons.bin",
		"phase2/closure/record.sig",
		"phase2/beacon/record.json",
	} {
		if err := CheckPublishable(name); err != nil {
			t.Errorf("CheckPublishable(%q) refused a real artifact: %v", name, err)
		}
	}
}

func TestDigestFileMatchesKnownVector(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, size, err := DigestFile(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if sum != want {
		t.Errorf("DigestFile = %s, want %s", sum, want)
	}
	if size != 3 {
		t.Errorf("size = %d, want 3", size)
	}
}

const hex64 = "1111111111111111111111111111111111111111111111111111111111111111"

func writeChain(t *testing.T, withSignature bool) (string, Chain) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "phase1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(dir, "chain-0000.json")
	signaturePath := filepath.Join(dir, "chain-0000.sig")
	if err := os.WriteFile(chainPath, []byte("chain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if withSignature {
		if err := os.WriteFile(signaturePath, []byte("sig"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, Chain{
		Schema:             chainInspectionSchema,
		CeremonyID:         "sha256:" + hex64,
		Phase:              "phase1",
		ChainPath:          chainPath,
		ChainSignaturePath: signaturePath,
		Artifacts: []ArtifactRef{{
			Name:   "phase1/genesis.bin",
			Digest: Digest{SHA256: "sha256:" + hex64, Blake2b256: "blake2b256:" + hex64, Size: 100},
		}},
	}
}

// TestTranscriptFilesIncludesChainAndSignature guards the gap this tool
// originally had: the chain document names every artifact, but nothing names
// the chain, so walking references alone leaves a bucket that cannot be
// interpreted or bootstrapped from.
func TestTranscriptFilesIncludesChainAndSignature(t *testing.T) {
	root, chain := writeChain(t, true)
	files, err := TranscriptFiles(root, chain)
	if err != nil {
		t.Fatalf("TranscriptFiles: %v", err)
	}
	names := map[string]bool{}
	for _, f := range files {
		names[f.Name] = true
	}
	for _, want := range []string{"phase1/genesis.bin", "phase1/chain-0000.json", "phase1/chain-0000.sig"} {
		if !names[want] {
			t.Errorf("TranscriptFiles omitted %s: got %v", want, names)
		}
	}
}

func TestTranscriptFilesRequiresChainSignature(t *testing.T) {
	root, chain := writeChain(t, false)
	if _, err := TranscriptFiles(root, chain); err == nil {
		t.Fatal("TranscriptFiles accepted a chain with no signature alongside it")
	}
}

// TestTranscriptFilesPicksUpPhaseEndingRecords covers the other half of that
// gap: closure, beacon and seal documents are unreachable from the chain, so
// they are listed by layout and included once they exist.
func TestTranscriptFilesPicksUpPhaseEndingRecords(t *testing.T) {
	root, chain := writeChain(t, true)
	for _, name := range []string{"closure/record.json", "closure/record.sig", "sealed/commons.bin"} {
		full := filepath.Join(root, "phase1", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := TranscriptFiles(root, chain)
	if err != nil {
		t.Fatalf("TranscriptFiles: %v", err)
	}
	names := map[string]bool{}
	for _, f := range files {
		names[f.Name] = true
	}
	for _, want := range []string{
		"phase1/closure/record.json",
		"phase1/closure/record.sig",
		"phase1/sealed/commons.bin",
	} {
		if !names[want] {
			t.Errorf("TranscriptFiles omitted %s", want)
		}
	}
	// A beacon that has not been recorded yet must not be an error: the same
	// command has to be correct at every stage of a phase.
	if names["phase1/beacon/record.json"] {
		t.Error("TranscriptFiles listed a beacon record that does not exist")
	}
}

func TestMirrorReceiptFilesIsSortedAndComplete(t *testing.T) {
	ref := func(name string) ArtifactRef {
		return ArtifactRef{Name: name, Digest: Digest{SHA256: "sha256:" + hex64, Size: 1}}
	}
	files := MirrorReceiptFiles(ChainRecord{Artifacts: []ArtifactRef{
		ref("phase1/contributions/0001/contribution.bin"),
		ref("phase1/contributions/0001/attestation.json"),
		ref("phase1/contributions/0001/attestation.sig"),
		ref("phase1/contributions/0001/erasure.json"),
		ref("phase1/contributions/0001/erasure.sig"),
		ref("phase1/contributions/0001/verification.json"),
	}}, ref("phase1/chain-0001.json"), ref("phase1/chain-0001.sig"))

	if len(files) != 8 {
		t.Fatalf("got %d files, want 8", len(files))
	}
	for i := 1; i < len(files); i++ {
		if files[i-1].Name >= files[i].Name {
			t.Fatalf("files are not sorted by name: %q then %q", files[i-1].Name, files[i].Name)
		}
	}
}
