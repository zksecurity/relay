package transcript

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// File is one artifact to sync: its logical name, and the digest it must have
// where that is known from a signed document.
//
// Digest is empty for files whose hash no signed document states. The chain
// document itself is the important case: nothing inside the transcript names
// it, because it is the thing doing the naming. Those files are still synced,
// because a bucket of payloads with no chain to interpret them is not a
// transcript, but their content is authenticated by the coordinator signature
// alongside them rather than by a digest this tool can check.
type File struct {
	Name   string
	Digest Digest // zero value means no signed digest is available
}

// HasDigest reports whether a signed document states this file's hash.
func (f File) HasDigest() bool { return f.Digest.SHA256 != "" }

// phaseEndingFiles are the documents that seal a phase. They are listed by
// layout rather than discovered from the chain, because the chain cannot
// reference them: a closure record names the chain head it closes, so the
// pointer runs backwards.
//
// Witnesses sign receipts binding the exact closure bytes, auditors pass the
// closure, beacon and seal to `audit` explicitly, and `phase2 init` consumes
// the phase-1 seal and commons. A mirror that omits them is not mirroring the
// transcript.
var phaseEndingFiles = map[string][]string{
	"phase1": {
		"phase1/closure/record.json",
		"phase1/closure/record.sig",
		"phase1/beacon/raw-response.bin",
		"phase1/beacon/record.json",
		"phase1/beacon/record.sig",
		"phase1/sealed/commons.bin",
		"phase1/sealed/seal.json",
		"phase1/sealed/seal.sig",
	},
	"phase2": {
		"phase2/closure/record.json",
		"phase2/closure/record.sig",
		"phase2/beacon/raw-response.bin",
		"phase2/beacon/record.json",
		"phase2/beacon/record.sig",
	},
}

// ceremonyRootFiles are the transcript-wide documents. Like the phase-ending
// records these are unreachable from the chain: the compiled constraint system
// is named by the ceremony definition, and the definition names itself.
//
// The coordinator public key is deliberately absent. It is the out-of-band
// trust anchor, and fetching it from the bucket whose contents it authenticates
// would prove only that the bucket agrees with itself.
var ceremonyRootFiles = []string{
	"ceremony.json",
	"ceremony.sig",
	"ownership-destination.ccs",
}

// TranscriptFiles returns everything a mirror of this phase must hold: the
// artifacts the chain names, the chain document and its signature, the
// transcript-wide documents, and whichever phase-ending records exist on disk.
//
// Phase-ending records are optional because a phase is mirrored repeatedly as it
// progresses. Before the closure is written there is nothing to sync; after it,
// there is. Absent files are skipped rather than being an error, so the same
// command is correct at every stage.
func TranscriptFiles(root string, chain Chain) ([]File, error) {
	files := make([]File, 0, len(chain.Artifacts)+10)
	for _, ref := range chain.Artifacts {
		files = append(files, File{Name: ref.Name, Digest: ref.Digest})
	}

	// The chain document names every contribution but nothing names the chain,
	// so it has to be added by hand. Without it and its signature a puller
	// cannot bootstrap, and a mirror receipt cannot list the accepted chain
	// prefix the ceremony requires.
	chainName, err := logicalName(root, chain.ChainPath)
	if err != nil {
		return nil, err
	}
	files = append(files, File{Name: chainName})
	signatureName := strings.TrimSuffix(chainName, ".json") + ".sig"
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(signatureName))); err == nil {
		files = append(files, File{Name: signatureName})
	} else {
		return nil, fmt.Errorf("chain signature %s is missing; the chain is unusable without it", signatureName)
	}

	for _, name := range append(append([]string(nil), ceremonyRootFiles...), phaseEndingFiles[chain.Phase]...) {
		full, err := Resolve(root, name)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() {
			continue // not written yet, or not a regular file
		}
		files = append(files, File{Name: name})
	}

	for _, file := range files {
		if err := CheckPublishable(file.Name); err != nil {
			return nil, err
		}
	}
	return files, nil
}

// logicalName expresses an absolute path as a transcript-relative logical name.
func logicalName(root, target string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return "", err
	}
	name := filepath.ToSlash(rel)
	if name == ".." || strings.HasPrefix(name, "../") {
		return "", fmt.Errorf("%s is outside the transcript root", target)
	}
	return path.Clean(name), nil
}
