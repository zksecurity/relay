package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

type publicationStore interface {
	Head(string) (bool, error)
	Size(string) (int64, error)
	Get(string, string) error
	PutNoReplace(string, string) error
}

func copyRecoverySnapshot(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("recovery inputs must be regular files, not links or special files")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(destination)
		return errors.Join(copyErr, closeErr)
	}
	return nil
}

func publicationLogicalName(root, target string, files []transcript.File) (string, error) {
	for _, file := range files {
		local, err := transcript.Resolve(root, file.Name)
		if err != nil {
			return "", err
		}
		if sameLocalPath(local, target) {
			return file.Name, nil
		}
	}
	return "", errors.New("authenticated publication file set does not contain a required input")
}

func snapshotInitialPublication(o roleOpts, chainPath, chainSignaturePath string) (roleOpts, transcript.Definition, transcript.Chain, []transcript.File, func(), error) {
	definition, err := o.inspector().Definition()
	if err != nil {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
	}
	chain, err := o.inspector().Chain(chainPath, chainSignaturePath)
	if err != nil {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
	}
	if chain.Phase != "phase1" || chain.AcceptedCount() != 0 {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, errors.New("recovery is limited to the retained initial phase1 publication at index 0")
	}
	files, err := transcript.TranscriptFiles(o.root, chain)
	if err != nil {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name, "phase1/closure/") || strings.HasPrefix(file.Name, "phase1/beacon/") || strings.HasPrefix(file.Name, "phase1/sealed/") {
			return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, errors.New("initial publication recovery refuses phase-ending files")
		}
	}
	definitionName, err := publicationLogicalName(o.root, o.definition, files)
	if err != nil {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
	}
	definitionSignatureName, err := publicationLogicalName(o.root, o.definitionSig, files)
	if err != nil {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
	}
	chainName, err := publicationLogicalName(o.root, chainPath, files)
	if err != nil {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
	}
	chainSignatureName, err := publicationLogicalName(o.root, chainSignaturePath, files)
	if err != nil {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
	}
	temp, err := os.MkdirTemp("", "relay-retained-publication-")
	if err != nil {
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(temp) }
	seen := map[string]bool{}
	for _, file := range files {
		if seen[file.Name] {
			cleanup()
			return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, fmt.Errorf("duplicate publication file %q", file.Name)
		}
		seen[file.Name] = true
		source, err := transcript.Resolve(o.root, file.Name)
		if err != nil {
			cleanup()
			return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
		}
		destination, err := transcript.Resolve(temp, file.Name)
		if err != nil {
			cleanup()
			return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
		}
		if err := copyRecoverySnapshot(source, destination); err != nil {
			cleanup()
			return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, fmt.Errorf("snapshot %s: %w", file.Name, err)
		}
	}
	trustedKey := filepath.Join(temp, ".trust", "coordinator-public-key.hex")
	if err := copyRecoverySnapshot(o.coordinatorKey, trustedKey); err != nil {
		cleanup()
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, fmt.Errorf("snapshot coordinator public key: %w", err)
	}
	snapshot := o
	snapshot.root = temp
	snapshot.definition = filepath.Join(temp, filepath.FromSlash(definitionName))
	snapshot.definitionSig = filepath.Join(temp, filepath.FromSlash(definitionSignatureName))
	snapshot.coordinatorKey = trustedKey
	snapshotChainPath := filepath.Join(temp, filepath.FromSlash(chainName))
	snapshotSignaturePath := filepath.Join(temp, filepath.FromSlash(chainSignatureName))
	snapshotDefinition, err := snapshot.inspector().Definition()
	if err != nil {
		cleanup()
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, fmt.Errorf("authenticate snapshotted definition: %w", err)
	}
	snapshotChain, err := snapshot.inspector().Chain(snapshotChainPath, snapshotSignaturePath)
	if err != nil {
		cleanup()
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, fmt.Errorf("authenticate snapshotted chain: %w", err)
	}
	snapshotFiles, err := transcript.TranscriptFiles(temp, snapshotChain)
	if err != nil || !reflect.DeepEqual(files, snapshotFiles) {
		cleanup()
		if err != nil {
			return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, err
		}
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, errors.New("publication file set changed while it was being snapshotted")
	}
	if !reflect.DeepEqual(definition, snapshotDefinition) || chain.Phase != snapshotChain.Phase || chain.AcceptedCount() != snapshotChain.AcceptedCount() {
		cleanup()
		return o, transcript.Definition{}, transcript.Chain{}, nil, func() {}, errors.New("authenticated publication changed while it was being snapshotted")
	}
	return snapshot, snapshotDefinition, snapshotChain, snapshotFiles, cleanup, nil
}

func verifyRemotePublicationObject(client publicationStore, key, source, label string) error {
	expected, expectedSize, err := transcript.DigestFile(source)
	if err != nil {
		return err
	}
	remoteSize, err := client.Size(key)
	if err != nil {
		return fmt.Errorf("inspect retained object size %s: %w", label, err)
	}
	if remoteSize != expectedSize {
		return fmt.Errorf("integrity conflict at %s: existing object size differs from the retained authenticated file", key)
	}
	dir, err := os.MkdirTemp("", "relay-publication-recovery-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	destination := filepath.Join(dir, "object")
	if err := client.Get(key, destination); err != nil {
		return fmt.Errorf("read retained object %s: %w", label, err)
	}
	actual, actualSize, err := transcript.DigestFile(destination)
	if err != nil {
		return err
	}
	if actual != expected || actualSize != expectedSize {
		return fmt.Errorf("integrity conflict at %s: existing object differs from the retained authenticated file", key)
	}
	return nil
}

func reconcilePublicationObject(client publicationStore, key, source, label string) error {
	present, err := client.Head(key)
	if err != nil {
		return fmt.Errorf("inspect retained object %s: %w", label, err)
	}
	if !present {
		putErr := client.PutNoReplace(key, source)
		if putErr != nil && !errors.Is(putErr, store.ErrExists) {
			// The request may have reached storage before the response failed. Read
			// the exact key before deciding whether another invocation is needed.
			if verifyErr := verifyRemotePublicationObject(client, key, source, label); verifyErr == nil {
				return nil
			} else {
				return errors.Join(fmt.Errorf("create retained object %s: %w", label, putErr), verifyErr)
			}
		}
	}
	return verifyRemotePublicationObject(client, key, source, label)
}

func decodeRecoveryPointer(raw []byte) (state.Pointer, error) {
	var pointer state.Pointer
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pointer); err != nil {
		return pointer, fmt.Errorf("decode existing phase head: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return pointer, errors.New("existing phase head has trailing JSON")
	}
	return pointer, pointer.Validate()
}

func equivalentInitialPointer(actual, expected state.Pointer) bool {
	updated, err := time.Parse(time.RFC3339, actual.UpdatedAt)
	if err != nil {
		return false
	}
	_, offset := updated.Zone()
	return actual.Schema == expected.Schema && actual.CeremonyID == expected.CeremonyID &&
		actual.Phase == "phase1" && actual.Index == 0 && !actual.Closed &&
		actual.Chain == expected.Chain && actual.ChainSignature == expected.ChainSignature &&
		reflect.DeepEqual(actual.Files, expected.Files) && offset == 0
}

func verifyExistingInitialPointer(client publicationStore, key string, expected state.Pointer) error {
	size, err := client.Size(key)
	if err != nil {
		return fmt.Errorf("inspect existing initial phase head size: %w", err)
	}
	if size <= 0 || size > 1<<20 {
		return errors.New("existing initial phase head exceeds the recovery size limit")
	}
	dir, err := os.MkdirTemp("", "relay-publication-head-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "head.json")
	if err := client.Get(key, path); err != nil {
		return fmt.Errorf("read existing initial phase head: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	actual, err := decodeRecoveryPointer(raw)
	if err != nil {
		return err
	}
	if !equivalentInitialPointer(actual, expected) {
		return errors.New("existing phase1 head is not the exact retained index-0 publication; stopped without overwriting it")
	}
	return nil
}

func reconcileInitialPointer(client publicationStore, key, pointerPath string, expected state.Pointer, present bool) error {
	if !present {
		putErr := client.PutNoReplace(key, pointerPath)
		if putErr != nil && !errors.Is(putErr, store.ErrExists) {
			if verifyErr := verifyExistingInitialPointer(client, key, expected); verifyErr != nil {
				return errors.Join(fmt.Errorf("create initial phase head: %w", putErr), verifyErr)
			}
		}
	}
	return verifyExistingInitialPointer(client, key, expected)
}

func validateRecoveryFile(file transcript.File, r1cs transcript.ArtifactRef, sum string, size int64) (bool, error) {
	if file.HasDigest() && (sum != file.Digest.SHA256 || size != file.Digest.Size) {
		return false, fmt.Errorf("%s: retained file does not match its authenticated chain digest", file.Name)
	}
	if file.Name != r1cs.Name {
		return false, nil
	}
	if sum != r1cs.Digest.SHA256 || size != r1cs.Digest.Size {
		return true, fmt.Errorf("%s: retained circuit does not match the signed ceremony definition", file.Name)
	}
	return true, nil
}

// recoverInitialPublication is intentionally narrower than ordinary publish.
// It can only finish phase1 index zero and every write is create-only.
func recoverInitialPublication(o roleOpts, chainPath, chainSignaturePath string) error {
	o, definition, chain, files, cleanup, err := snapshotInitialPublication(o, chainPath, chainSignaturePath)
	if err != nil {
		return err
	}
	defer cleanup()
	chainPath = chain.ChainPath
	chainSignaturePath = chain.ChainSignaturePath
	r1cs, err := definition.R1CS()
	if err != nil {
		return err
	}
	type plannedObject struct {
		name, local, sum string
	}
	var plan []plannedObject
	var chainRef, signatureRef state.Ref
	r1csFound := false
	refs := make([]state.Ref, 0, len(files))
	for _, file := range files {
		local, err := transcript.Resolve(o.root, file.Name)
		if err != nil {
			return err
		}
		sum, size, err := transcript.DigestFile(local)
		if err != nil {
			return fmt.Errorf("%s: %w", file.Name, err)
		}
		isR1CS, err := validateRecoveryFile(file, r1cs, sum, size)
		if err != nil {
			return err
		}
		if isR1CS {
			r1csFound = true
		}
		ref := state.Ref{Name: file.Name, SHA256: sum}
		refs = append(refs, ref)
		if sameLocalPath(local, chainPath) {
			chainRef = ref
		}
		if sameLocalPath(local, chainSignaturePath) {
			signatureRef = ref
		}
		plan = append(plan, plannedObject{name: file.Name, local: local, sum: sum})
	}
	if chainRef.Name == "" || signatureRef.Name == "" {
		return errors.New("authenticated file set did not contain the retained chain and signature")
	}
	if !r1csFound {
		return errors.New("authenticated file set did not contain the circuit named by the signed definition")
	}
	pointer := state.Pointer{Schema: state.Schema, CeremonyID: definition.CeremonyID, Phase: "phase1", Index: 0, Chain: chainRef, ChainSignature: signatureRef, UpdatedAt: time.Now().UTC().Format(time.RFC3339), Files: refs}
	key := state.Key(definition.CeremonyID, "phase1")
	headPresent, err := o.client.Head(key)
	if err != nil {
		return fmt.Errorf("inspect initial phase head: %w", err)
	}
	if headPresent {
		if err := verifyExistingInitialPointer(o.client, key, pointer); err != nil {
			return err
		}
	}
	for _, object := range plan {
		if err := reconcilePublicationObject(o.client, store.Key(object.sum), object.local, object.name); err != nil {
			return err
		}
		fmt.Printf("  verified %s\n", object.name)
	}
	encoded, err := pointer.Encode()
	if err != nil {
		return err
	}
	temp, err := os.MkdirTemp("", "relay-publication-pointer-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	pointerPath := filepath.Join(temp, "head.json")
	if err := os.WriteFile(pointerPath, encoded, 0o600); err != nil {
		return err
	}
	if err := reconcileInitialPointer(o.client, key, pointerPath, pointer, headPresent); err != nil {
		return err
	}
	fmt.Println("reconciled the retained phase1 index-0 publication; no object was overwritten")
	return nil
}
