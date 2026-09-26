package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/state"
)

// The decision verifier needs the entire authenticated final release tree as
// well as the newly generated reports. Its release reader rejects hardlinks,
// so each staged file must have its own inode. Use filesystem clones when
// available and a bounded streamed copy otherwise.
func workflowV4DecisionPrepareEvidenceRoot(work string, refs []state.ContentRef, stage string) (string, func() error, error) {
	public := filepath.Join(work, "ceremony", "public")
	if err := requireOfflineRealPath(public); err != nil {
		return "", nil, err
	}
	root, err := os.MkdirTemp(filepath.Join(work, "workflow-v4", "decision"), ".prepare-evidence-*")
	if err != nil {
		return "", nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = os.RemoveAll(root)
		}
	}()
	type stagedFile struct {
		source, target, digest string
		size                   int64
	}
	staged := make([]stagedFile, 0, len(refs)+8)
	seen := map[string]bool{}
	add := func(name, source, digest string, size int64) error {
		if !filepath.IsLocal(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.ContainsAny(name, "\\\r\n\x1b") || seen[name] || size < 0 || size == math.MaxInt64 || !strings.HasPrefix(digest, "sha256:") {
			return fmt.Errorf("invalid or duplicate decision evidence path %q", name)
		}
		seen[name] = true
		if err := requireOfflineRealPath(filepath.Dir(source)); err != nil {
			return err
		}
		if err := workflowV4VerifyDecisionInputFile(source, digest, size); err != nil {
			return err
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		if err := workflowV4CloneOrCopyDecisionInput(source, target); err != nil {
			return fmt.Errorf("stage authenticated decision input %q: %w", name, err)
		}
		if err := workflowV4VerifyDecisionInputFile(target, digest, size); err != nil {
			return err
		}
		staged = append(staged, stagedFile{source, target, digest, size})
		return nil
	}
	for _, ref := range refs {
		if ref.Name == "decision" || strings.HasPrefix(ref.Name, "decision/") || ref.Name == "draft.json" {
			return "", nil, errors.New("authenticated release file collides with generated decision files")
		}
		if err := add(ref.Name, filepath.Join(public, filepath.FromSlash(ref.Name)), ref.SHA256, ref.Size); err != nil {
			return "", nil, err
		}
	}
	evidence := filepath.Join(stage, "decision", "evidence")
	if err := requireOfflineRealPath(evidence); err != nil {
		return "", nil, err
	}
	entries, err := os.ReadDir(evidence)
	if err != nil {
		return "", nil, err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return "", nil, errors.New("generated decision evidence contains a non-regular file")
		}
		source := filepath.Join(evidence, entry.Name())
		info, err := os.Lstat(source)
		if err != nil || info.Size() <= 0 || info.Size() > 16<<20 {
			return "", nil, fmt.Errorf("invalid generated decision evidence %q", entry.Name())
		}
		digest, _, err := workflowV4FileSHA256(source, 16<<20)
		if err != nil {
			return "", nil, err
		}
		if err := add("decision/evidence/"+entry.Name(), source, digest, info.Size()); err != nil {
			return "", nil, err
		}
	}
	verify := func() error {
		for _, item := range staged {
			if err := workflowV4VerifyDecisionInputFile(item.source, item.digest, item.size); err != nil {
				return err
			}
			if err := workflowV4VerifyDecisionInputFile(item.target, item.digest, item.size); err != nil {
				return err
			}
			sourceInfo, sourceErr := os.Lstat(item.source)
			targetInfo, targetErr := os.Lstat(item.target)
			if sourceErr != nil || targetErr != nil || os.SameFile(sourceInfo, targetInfo) {
				return fmt.Errorf("decision preparation input does not have an independent inode: %s", item.target)
			}
		}
		return nil
	}
	failed = false
	return root, verify, nil
}

func workflowV4CloneOrCopyDecisionInput(source, target string) error {
	cloned, err := workflowV4CloneDecisionInput(source, target)
	if err != nil || cloned {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	if copyErr == nil {
		copyErr = output.Sync()
	}
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func workflowV4VerifyDecisionInputFile(path, digest string, size int64) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != size {
		return fmt.Errorf("decision preparation input changed or is not a regular file: %s", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, size+1))
	if err != nil || n != size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != digest {
		return fmt.Errorf("decision preparation input differs from authenticated bytes: %s", path)
	}
	return nil
}
