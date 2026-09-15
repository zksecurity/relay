package storagefirst

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const LocalFactsSchema = "relay-storage-first-local-facts-v1"

func validateLocalFacts(facts LocalFacts) error {
	if facts.Schema != LocalFactsSchema {
		return fmt.Errorf("local facts schema %q, want %q", facts.Schema, LocalFactsSchema)
	}
	if facts.Role != Coordinator && facts.Role != Participant {
		return errors.New("local facts role is invalid")
	}
	if facts.Role == Participant && !validComponent(facts.IdentityID) {
		return errors.New("participant local facts require an identity")
	}
	seen := map[string]struct{}{}
	for i, fact := range facts.Operations {
		if err := fact.Validate(); err != nil {
			return fmt.Errorf("operation %d: %w", i, err)
		}
		if facts.Role == Participant && fact.IdentityID != facts.IdentityID {
			return fmt.Errorf("operation %d belongs to another participant", i)
		}
		key := string(fact.Kind) + "\x00" + fact.CheckpointDigest + "\x00" + fact.Phase + "\x00" + fmt.Sprint(fact.Index) + "\x00" + fact.IdentityID + "\x00" + fact.AttemptID + "\x00" + fact.ArtifactDigest
		if _, ok := seen[key]; ok {
			return fmt.Errorf("operation %d duplicates an exact durable fact", i)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (f OperationFact) Validate() error {
	switch f.Kind {
	case OperationOutboundDownloaded, OperationReceiptUploaded, OperationCandidateGrant, OperationCandidateComputed, OperationCandidateUploaded:
	default:
		return fmt.Errorf("unsupported operation kind %q", f.Kind)
	}
	if !validDigest(f.CheckpointDigest) || !validDigest(f.ArtifactDigest) {
		return errors.New("operation checkpoint and artifact digests must be tagged SHA-256")
	}
	if f.Phase != "phase1" || f.Index < 1 || f.Index > 255 || !validComponent(f.IdentityID) || !validAttempt(f.AttemptID) {
		return errors.New("operation scope is invalid")
	}
	if f.Kind == OperationCandidateGrant {
		parsed, err := time.Parse(time.RFC3339, f.GrantExpiresAt)
		if err != nil || f.GrantExpiresAt != parsed.UTC().Format(time.RFC3339) {
			return errors.New("candidate grant fact requires canonical RFC3339 UTC expiry")
		}
	} else if f.GrantExpiresAt != "" {
		return errors.New("only candidate grant facts may contain grant expiry")
	}
	return nil
}

func SaveLocalFacts(path string, facts LocalFacts) error {
	if err := validateLocalFacts(facts); err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("local facts path must be absolute and clean")
	}
	raw, err := json.MarshalIndent(facts, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	unlock, err := lockLocalFacts(path + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	if existing, err := LoadLocalFacts(path); err == nil {
		if !factsContain(facts, existing) {
			return errors.New("local facts changed since they were read; reload before saving")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing local facts before save: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".local-facts-")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	keep := false
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = os.Remove(tempName)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temp.Write(raw); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	keep = true
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func factsContain(next, previous LocalFacts) bool {
	if next.Schema != previous.Schema || next.Role != previous.Role || next.IdentityID != previous.IdentityID {
		return false
	}
	for _, required := range previous.Operations {
		found := false
		for _, candidate := range next.Operations {
			if candidate == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func LoadLocalFacts(path string) (LocalFacts, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return LocalFacts{}, errors.New("local facts path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return LocalFacts{}, err
	}
	if !info.Mode().IsRegular() {
		return LocalFacts{}, errors.New("local facts must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > 1<<20 {
		return LocalFacts{}, errors.New("local facts size is outside the allowed range")
	}
	file, err := os.Open(path)
	if err != nil {
		return LocalFacts{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var facts LocalFacts
	if err := decoder.Decode(&facts); err != nil {
		return LocalFacts{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return LocalFacts{}, errors.New("local facts contain trailing JSON")
	}
	if err := validateLocalFacts(facts); err != nil {
		return LocalFacts{}, err
	}
	return facts, nil
}

func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, r := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func validAttempt(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func validComponent(value string) bool {
	return value != "" && len(value) <= 128 && filepath.Base(value) == value && value != "." && value != ".." && !strings.ContainsAny(value, `/\\`)
}
