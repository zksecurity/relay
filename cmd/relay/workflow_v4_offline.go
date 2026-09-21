package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

const offlineSnapshotFile = "relay-public-snapshot.json"

type workflowV4PublicSnapshot struct {
	Schema string             `json:"schema"`
	Root   state.Root         `json:"root"`
	Files  []state.ContentRef `json:"files"`
}

type workflowV4OfflineStore struct {
	directory string
	root      state.Root
	rootBytes []byte
	files     map[string]state.ContentRef
}

// This transport is untrusted. Normal SyncV4 verifies every reference, signed
// ancestor and assignment against the separately installed coordinator key.
func openWorkflowV4OfflineStore(directory string) (*workflowV4OfflineStore, error) {
	if err := requireOfflineRealPath(directory); err != nil {
		return nil, err
	}
	raw, err := readTesseraRegularFile(filepath.Join(directory, offlineSnapshotFile), 16<<20, false)
	if err != nil {
		return nil, err
	}
	if err := rejectCommitJournalDuplicateFields(raw); err != nil {
		return nil, err
	}
	var manifest workflowV4PublicSnapshot
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("public snapshot has trailing data")
	}
	if manifest.Schema != "relay-public-snapshot-v1" || len(manifest.Files) == 0 || len(manifest.Files) > 65536 {
		return nil, errors.New("invalid public snapshot inventory")
	}
	if err := manifest.Root.Validate(); err != nil {
		return nil, err
	}
	rootBytes, err := manifest.Root.Encode()
	if err != nil {
		return nil, err
	}
	result := &workflowV4OfflineStore{directory: directory, root: manifest.Root, rootBytes: rootBytes, files: map[string]state.ContentRef{}}
	allowed := map[string]bool{offlineSnapshotFile: true, "objects": true}
	names := map[string]bool{}
	for _, ref := range manifest.Files {
		digest := strings.TrimPrefix(ref.SHA256, "sha256:")
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != 32 || ref.SHA256 != "sha256:"+hex.EncodeToString(decoded) || ref.Size <= 0 || ref.Size > 16<<30 || names[ref.Name] {
			return nil, errors.New("invalid public snapshot reference")
		}
		if ref.Name == "" || filepath.IsAbs(ref.Name) || filepath.ToSlash(filepath.Clean(ref.Name)) != ref.Name || ref.Name == "." || ref.Name == ".." || strings.HasPrefix(ref.Name, "../") || strings.Contains(ref.Name, `\`) {
			return nil, errors.New("unsafe public snapshot name")
		}
		names[ref.Name] = true
		key := store.Key(ref.SHA256)
		if previous, ok := result.files[key]; ok && previous.Size != ref.Size {
			return nil, errors.New("conflicting public snapshot digest")
		}
		result.files[key] = ref
		allowed["objects/"+digest] = true
	}
	err = filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if !allowed[filepath.ToSlash(relative)] || entry.Type()&os.ModeSymlink != 0 || (!entry.IsDir() && !entry.Type().IsRegular()) {
			return errors.New("public snapshot contains an unexpected file or symbolic link")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *workflowV4OfflineStore) GetVersionedAtMost(key, path string, maximum int64) (store.ObjectVersion, error) {
	if maximum <= 0 || maximum > 16<<30 {
		return store.ObjectVersion{}, errors.New("invalid offline object bound")
	}
	var input io.Reader
	var file *os.File
	if key == state.RootKey(s.root.CeremonyID) {
		input = bytes.NewReader(s.rootBytes)
	} else {
		ref, ok := s.files[key]
		if !ok {
			return store.ObjectVersion{}, errors.New("object absent from offline public snapshot")
		}
		if ref.Size > maximum {
			return store.ObjectVersion{}, errors.New("offline object exceeds requested bound")
		}
		source := filepath.Join(s.directory, "objects", strings.TrimPrefix(ref.SHA256, "sha256:"))
		if err := requireOfflineRealPath(source); err != nil {
			return store.ObjectVersion{}, err
		}
		var err error
		file, err = os.Open(source)
		if err != nil {
			return store.ObjectVersion{}, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return store.ObjectVersion{}, err
		}
		if !info.Mode().IsRegular() || info.Size() != ref.Size {
			return store.ObjectVersion{}, errors.New("offline object size or type changed")
		}
		input = file
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return store.ObjectVersion{}, err
	}
	if err := requireOfflineRealPath(filepath.Dir(path)); err != nil {
		return store.ObjectVersion{}, err
	}
	output, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return store.ObjectVersion{}, err
	}
	digest := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(output, digest), io.LimitReader(input, maximum+1))
	closeErr := output.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return store.ObjectVersion{}, err
	}
	if size > maximum {
		return store.ObjectVersion{}, errors.New("offline object exceeds requested bound")
	}
	return store.ObjectVersion{ETag: fmt.Sprintf("\"%x\"", digest.Sum(nil)), Size: size}, nil
}

// Export only the authenticated public inventory, never an entire role folder.
// The completion manifest is written last; an interrupted export cannot open.
func exportWorkflowV4PublicSnapshot(snapshot storagefirst.SnapshotV4, work, destination string) error {
	if _, err := snapshot.State(); err != nil {
		return err
	}
	if _, err := pathWithin(work, destination, "/work"); err != nil {
		return err
	}
	if err := requireOfflineRealPath(filepath.Dir(destination)); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return fmt.Errorf("fresh public export directory required: %w", err)
	}
	objects := filepath.Join(destination, "objects")
	if err := os.Mkdir(objects, 0700); err != nil {
		return err
	}
	root, _ := snapshot.Root()
	manifest := workflowV4PublicSnapshot{Schema: "relay-public-snapshot-v1", Root: root, Files: snapshot.Files()}
	seen := map[string]bool{}
	for _, ref := range manifest.Files {
		if seen[ref.SHA256] {
			continue
		}
		seen[ref.SHA256] = true
		source := filepath.Join(work, "ceremony", "public", filepath.FromSlash(ref.Name))
		if err := requireOfflineRealPath(source); err != nil {
			return err
		}
		in, err := os.Open(source)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(objects, strings.TrimPrefix(ref.SHA256, "sha256:")), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			in.Close()
			return err
		}
		digest := sha256.New()
		size, copyErr := io.Copy(io.MultiWriter(out, digest), io.LimitReader(in, ref.Size+1))
		inErr := in.Close()
		syncErr := out.Sync()
		outErr := out.Close()
		if err := errors.Join(copyErr, inErr, syncErr, outErr); err != nil {
			return err
		}
		if size != ref.Size || fmt.Sprintf("sha256:%x", digest.Sum(nil)) != ref.SHA256 {
			return errors.New("public artifact changed during export")
		}
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return setupWriteBytesNewOrExact(filepath.Join(destination, offlineSnapshotFile), raw, 0600)
}

func runWorkflowV4OfflineHandoff(ui *coordinatorWizard, action string, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, online, signer guidedProfile, inspector transcript.Inspector, config access.StorageConfig, enrollment *transcript.ExpectedEnrollment) error {
	switch action {
	case "E":
		destination, err := ui.required("Fresh public export directory inside this coordinator workspace", "")
		if err != nil {
			return err
		}
		if err := exportWorkflowV4PublicSnapshot(snapshot, online.Work, destination); err != nil {
			return err
		}
		fmt.Fprintf(ui.output, "Transfer only this public directory: %s\nAuthenticate the coordinator key separately. Never transfer role workspaces or keys.\n", destination)
		return nil
	case "I":
		if enrollment == nil || enrollment.Role != "release-signer" {
			return errors.New("no offline release-signer enrollment is pending")
		}
		source, err := ui.required("Directory containing the offline signer's prepared public enrollment (preserve its original layout; never transfer keys)", "")
		if err != nil {
			return err
		}
		if err := requireOfflineRealPath(source); err != nil {
			return err
		}
		if err := ui.confirm("Verify this signer's enrollment and disclosure against the signed assignment, then record them", "VERIFY AND RECORD ENROLLMENT"); err != nil {
			return err
		}
		return prepareAndCommitWorkflowV4Enrollment(snapshot, protocol, online, signer, *enrollment, source)
	case "U":
		stateView, err := snapshot.State()
		if err != nil {
			return err
		}
		if stateView.Progress.ReleaseReview == nil || stateView.Progress.FinalRelease != nil {
			return errors.New("no unsigned final release is pending")
		}
		expected, err := workflowV4ReleaseSignerAssignment(protocol)
		if err != nil {
			return err
		}
		source, err := ui.required("Returned signed public package directory inside this online workspace (never import the signer's key or profile)", "")
		if err != nil {
			return err
		}
		if _, err := pathWithin(online.Work, source, "/work"); err != nil {
			return err
		}
		return runWorkflowV4ReleaseUpload(ui, snapshot, protocol, config, online, expected.Identity.ID, expected.Identity.KeyID, workflowV4ReleaseSignerProgress{PackageReady: true, PackageDir: source})
	}
	return errors.New("unknown public handoff")
}

func requireOfflineRealPath(path string) error {
	if err := validateCommitLocalPath(path); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != path {
		return errors.New("public handoff path must not contain symbolic links")
	}
	return nil
}
