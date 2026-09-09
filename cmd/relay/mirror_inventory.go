package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zksecurity/relay/internal/transcript"
)

// The mutable inventory supplies discovery only. Signed references override it;
// separately supplied trust anchors are never fetched or replaced from storage.
func mirrorSyncFiles(pos position) ([]transcript.File, error) {
	files := map[string]transcript.File{}
	if len(pos.pointer.Files) > 10000 {
		return nil, fmt.Errorf("published inventory is too large")
	}
	for _, ref := range pos.pointer.Files {
		if ref.Name == "coordinator-public-key.hex" {
			continue
		}
		if err := transcript.CheckPublishable(ref.Name); err != nil {
			return nil, err
		}
		digest, err := hex.DecodeString(strings.TrimPrefix(ref.SHA256, "sha256:"))
		if err != nil || len(digest) != 32 || !strings.HasPrefix(ref.SHA256, "sha256:") {
			return nil, fmt.Errorf("invalid inventory digest")
		}
		if _, exists := files[ref.Name]; exists {
			return nil, fmt.Errorf("duplicate inventory name")
		}
		files[ref.Name] = transcript.File{Name: ref.Name, Digest: transcript.Digest{SHA256: ref.SHA256, Size: -1}}
	}
	refs := append([]transcript.ArtifactRef(nil), pos.chain.Artifacts...)
	circuit, err := pos.definition.R1CS()
	if err != nil {
		return nil, err
	}
	refs = append(refs, circuit)
	for _, ref := range refs {
		if err := transcript.CheckPublishable(ref.Name); err != nil {
			return nil, err
		}
		if existing, ok := files[ref.Name]; ok && existing.Digest.SHA256 != ref.Digest.SHA256 {
			return nil, fmt.Errorf("inventory conflicts with a signed reference: %s", ref.Name)
		}
		files[ref.Name] = transcript.File{Name: ref.Name, Digest: ref.Digest}
	}
	for _, ref := range []struct{ Name, SHA256 string }{{pos.pointer.Chain.Name, pos.pointer.Chain.SHA256}, {pos.pointer.ChainSignature.Name, pos.pointer.ChainSignature.SHA256}} {
		if old, ok := files[ref.Name]; ok && old.Digest.SHA256 != ref.SHA256 {
			return nil, fmt.Errorf("inventory conflicts with authenticated current chain")
		}
		files[ref.Name] = transcript.File{Name: ref.Name, Digest: transcript.Digest{SHA256: ref.SHA256, Size: -1}}
	}
	for _, name := range []string{"ceremony.json", "ceremony.sig"} {
		if _, ok := files[name]; !ok {
			return nil, fmt.Errorf("published inventory omits %s; ask the coordinator to republish with the current CLI", name)
		}
	}
	for index := 0; index <= pos.accepted; index++ {
		for _, extension := range []string{"json", "sig"} {
			name := fmt.Sprintf("%s/chain-%04d.%s", pos.chain.Phase, index, extension)
			if _, ok := files[name]; !ok {
				return nil, fmt.Errorf("published inventory omits historical prefix %s; ask the coordinator to republish", name)
			}
		}
	}
	if pos.pointer.Closed {
		for _, extension := range []string{"json", "sig"} {
			name := fmt.Sprintf("%s/closure/record.%s", pos.chain.Phase, extension)
			if _, ok := files[name]; !ok {
				return nil, fmt.Errorf("closed phase inventory omits %s", name)
			}
		}
	}
	result := make([]transcript.File, 0, len(files))
	for _, file := range files {
		result = append(result, file)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func checkMirrorDestination(root, path string) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular())) {
			return fmt.Errorf("mirror destination contains a symlink or special file")
		}
		if current == root {
			return nil
		}
		if filepath.Dir(current) == current {
			return fmt.Errorf("mirror destination escapes root")
		}
	}
}
