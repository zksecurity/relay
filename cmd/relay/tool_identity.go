package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	toolIdentityReceiptSchema = "ceremony-kit-tool-identity-receipt-v1"
	maxToolIdentityReceipt    = 16 << 10
)

var (
	repositoryIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	releaseTagPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	sha256HexPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type toolIdentity struct {
	VerifiedPath string
	Repository   string
	Version      string
	ReleaseID    string
	SHA256       string
}

type toolIdentityReceipt struct {
	Schema            string
	KitMode           string
	KitRoot           string
	CompatibilityTest string
	Relay             toolIdentity
	MPCCeremony       toolIdentity
}

type verifiedToolIdentities struct {
	Receipt         toolIdentityReceipt
	RelayPath       string
	MPCCeremonyPath string
}

func verifyToolIdentities(receiptPath, ceremonyBinary string) (verifiedToolIdentities, error) {
	receipt, err := loadToolIdentityReceipt(receiptPath)
	if err != nil {
		return verifiedToolIdentities{}, err
	}
	relayExecutable, err := os.Executable()
	if err != nil {
		return verifiedToolIdentities{}, fmt.Errorf("resolve running Relay executable: %w", err)
	}
	relayPath, relaySHA256, err := resolveAndHashExecutable(relayExecutable)
	if err != nil {
		return verifiedToolIdentities{}, fmt.Errorf("authenticate running Relay executable: %w", err)
	}
	if relaySHA256 != receipt.Relay.SHA256 {
		return verifiedToolIdentities{}, fmt.Errorf(
			"running Relay SHA-256 %s does not match approved release %s",
			relaySHA256,
			receipt.Relay.ReleaseID,
		)
	}
	mpcPath, mpcSHA256, err := resolveAndHashExecutable(ceremonyBinary)
	if err != nil {
		return verifiedToolIdentities{}, fmt.Errorf("authenticate mpc-ceremony executable: %w", err)
	}
	if mpcSHA256 != receipt.MPCCeremony.SHA256 {
		return verifiedToolIdentities{}, fmt.Errorf(
			"mpc-ceremony SHA-256 %s does not match approved release %s",
			mpcSHA256,
			receipt.MPCCeremony.ReleaseID,
		)
	}
	return verifiedToolIdentities{
		Receipt:         receipt,
		RelayPath:       relayPath,
		MPCCeremonyPath: mpcPath,
	}, nil
}

func loadToolIdentityReceipt(path string) (toolIdentityReceipt, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return toolIdentityReceipt{}, fmt.Errorf("inspect tool identity receipt: %w", err)
	}
	if !info.Mode().IsRegular() {
		return toolIdentityReceipt{}, errors.New("tool identity receipt must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > maxToolIdentityReceipt {
		return toolIdentityReceipt{}, fmt.Errorf("tool identity receipt size %d is outside [1,%d]", info.Size(), maxToolIdentityReceipt)
	}
	file, err := os.Open(path)
	if err != nil {
		return toolIdentityReceipt{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return toolIdentityReceipt{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		return toolIdentityReceipt{}, errors.New("tool identity receipt changed while being opened")
	}
	limited := io.LimitReader(file, maxToolIdentityReceipt+1)
	reader := bufio.NewReader(limited)
	if first, err := reader.Peek(1); err == nil && first[0] == '{' {
		raw, err := io.ReadAll(reader)
		if err != nil {
			return toolIdentityReceipt{}, err
		}
		if len(raw) > maxToolIdentityReceipt {
			return toolIdentityReceipt{}, errors.New("tool receipt too large")
		}
		return decodeReleaseToolReceipt(raw)
	}
	values := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found || name == "" || value == "" {
			return toolIdentityReceipt{}, errors.New("tool identity receipt contains a malformed assignment")
		}
		switch name {
		case "TOOL_IDENTITY_RECEIPT_SCHEMA", "KIT_MODE", "KIT_ROOT", "COMPATIBILITY_TEST",
			"RELAY_VERIFIED_PATH", "RELAY_REPOSITORY", "RELAY_VERSION", "RELAY_RELEASE_ID", "RELAY_SHA256",
			"MPC_CEREMONY_VERIFIED_PATH", "MPC_CEREMONY_REPOSITORY", "MPC_CEREMONY_VERSION",
			"MPC_CEREMONY_RELEASE_ID", "MPC_CEREMONY_SHA256":
		default:
			return toolIdentityReceipt{}, fmt.Errorf("tool identity receipt contains unknown field %s", name)
		}
		if _, duplicate := values[name]; duplicate {
			return toolIdentityReceipt{}, fmt.Errorf("tool identity receipt repeats %s", name)
		}
		values[name] = value
	}
	if err := scanner.Err(); err != nil {
		return toolIdentityReceipt{}, fmt.Errorf("read tool identity receipt: %w", err)
	}
	if len(values) != 14 {
		return toolIdentityReceipt{}, fmt.Errorf("tool identity receipt has %d fields, want 14", len(values))
	}
	receipt := toolIdentityReceipt{
		Schema:            values["TOOL_IDENTITY_RECEIPT_SCHEMA"],
		KitMode:           values["KIT_MODE"],
		KitRoot:           values["KIT_ROOT"],
		CompatibilityTest: values["COMPATIBILITY_TEST"],
		Relay: toolIdentity{
			VerifiedPath: values["RELAY_VERIFIED_PATH"],
			Repository:   values["RELAY_REPOSITORY"],
			Version:      values["RELAY_VERSION"],
			ReleaseID:    values["RELAY_RELEASE_ID"],
			SHA256:       values["RELAY_SHA256"],
		},
		MPCCeremony: toolIdentity{
			VerifiedPath: values["MPC_CEREMONY_VERIFIED_PATH"],
			Repository:   values["MPC_CEREMONY_REPOSITORY"],
			Version:      values["MPC_CEREMONY_VERSION"],
			ReleaseID:    values["MPC_CEREMONY_RELEASE_ID"],
			SHA256:       values["MPC_CEREMONY_SHA256"],
		},
	}
	if err := receipt.validate(); err != nil {
		return toolIdentityReceipt{}, err
	}
	return receipt, nil
}

func (r toolIdentityReceipt) validate() error {
	if r.Schema != toolIdentityReceiptSchema {
		return fmt.Errorf("tool identity receipt schema %q, want %q", r.Schema, toolIdentityReceiptSchema)
	}
	if r.KitMode != "production" && r.KitMode != "rehearsal" {
		return errors.New("tool identity receipt has an invalid ceremony-kit mode")
	}
	if !filepath.IsAbs(r.KitRoot) || filepath.Clean(r.KitRoot) != r.KitRoot {
		return errors.New("tool identity receipt kit root must be an absolute clean path")
	}
	if r.CompatibilityTest != "tiny-rehearsal-phase1-contribution-v1" {
		return errors.New("tool identity receipt has an unrecognized compatibility test")
	}
	if err := r.Relay.validate("Relay"); err != nil {
		return err
	}
	return r.MPCCeremony.validate("mpc-ceremony")
}

func (i toolIdentity) validate(label string) error {
	if !filepath.IsAbs(i.VerifiedPath) || filepath.Clean(i.VerifiedPath) != i.VerifiedPath {
		return fmt.Errorf("%s verified path must be absolute and clean", label)
	}
	if !repositoryIDPattern.MatchString(i.Repository) {
		return fmt.Errorf("%s repository is invalid", label)
	}
	if !releaseTagPattern.MatchString(i.Version) {
		return fmt.Errorf("%s version is invalid", label)
	}
	if i.ReleaseID != i.Repository+"@"+i.Version {
		return fmt.Errorf("%s release identifier does not match its repository and version", label)
	}
	if !sha256HexPattern.MatchString(i.SHA256) {
		return fmt.Errorf("%s SHA-256 is invalid", label)
	}
	return nil
}

func resolveAndHashExecutable(name string) (string, string, error) {
	path := name
	if !strings.ContainsRune(name, filepath.Separator) {
		resolved, err := exec.LookPath(name)
		if err != nil {
			return "", "", err
		}
		path = resolved
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", "", err
	}
	before, err := os.Lstat(resolved)
	if err != nil {
		return "", "", err
	}
	if !before.Mode().IsRegular() || before.Mode()&0o111 == 0 {
		return "", "", errors.New("resolved executable is not an executable regular file")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", "", err
	}
	after, err := file.Stat()
	if err != nil {
		return "", "", err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() {
		return "", "", errors.New("resolved executable changed while being hashed")
	}
	return resolved, hex.EncodeToString(digest.Sum(nil)), nil
}

func formatToolIdentityVerification(verified verifiedToolIdentities) string {
	if verified.Receipt.Schema == releaseToolReceiptSchema {
		return fmt.Sprintf("Release tools match the local preparation record.\nRelay: %s\n  release: %s\n  sha256: %s\nmpc-ceremony: %s\n  release: %s\n  sha256: %s\nThis record measures tool identities; it does not claim a ceremony compatibility test or physical erasure. Ceremony policy is checked separately against its signed definition.\n", verified.RelayPath, verified.Receipt.Relay.ReleaseID, verified.Receipt.Relay.SHA256, verified.MPCCeremonyPath, verified.Receipt.MPCCeremony.ReleaseID, verified.Receipt.MPCCeremony.SHA256)
	}
	return fmt.Sprintf(
		"tool identity receipt: %s (%s)\nkit root: %s\nRelay: %s\n  release: %s\n  version: %s\n  sha256: %s\nmpc-ceremony: %s\n  release: %s\n  version: %s\n  sha256: %s\ncompatibility: %s\n",
		verified.Receipt.Schema,
		verified.Receipt.KitMode,
		verified.Receipt.KitRoot,
		verified.RelayPath,
		verified.Receipt.Relay.ReleaseID,
		verified.Receipt.Relay.Version,
		verified.Receipt.Relay.SHA256,
		verified.MPCCeremonyPath,
		verified.Receipt.MPCCeremony.ReleaseID,
		verified.Receipt.MPCCeremony.Version,
		verified.Receipt.MPCCeremony.SHA256,
		verified.Receipt.CompatibilityTest,
	)
}
