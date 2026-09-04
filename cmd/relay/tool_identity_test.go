package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSetupVerifyWritesConsumableToolIdentityReceipt(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ceremony kit targets Linux and requires GNU realpath")
	}
	root := t.TempDir()
	kit := filepath.Join(root, "kit")
	if err := os.Mkdir(kit, 0o700); err != nil {
		t.Fatal(err)
	}
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	setupBytes, err := os.ReadFile(filepath.Join(repositoryRoot, "scripts", "setup-ceremony-kit.sh"))
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, filepath.Join(kit, "setup"), setupBytes, 0o755)
	writeFixtureFile(t, filepath.Join(kit, "relay"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	writeFixtureFile(t, filepath.Join(kit, "mpc-ceremony"), []byte("#!/bin/sh\nexit 0\n# proof\n"), 0o755)
	writeFixtureFile(t, filepath.Join(kit, "storage-setup.tar.gz"), []byte("test storage archive"), 0o644)
	relayHash := fileSHA256ForTest(t, filepath.Join(kit, "relay"))
	mpcHash := fileSHA256ForTest(t, filepath.Join(kit, "mpc-ceremony"))
	releaseEnv := fmt.Sprintf(
		"KIT_SCHEMA=ceremony-kit-v1\n"+
			"KIT_MODE=production\n"+
			"RELAY_REPOSITORY=zksecurity/relay\n"+
			"RELAY_TAG=v1.2.3\n"+
			"RELAY_SHA256=%s\n"+
			"MPC_RELEASE_REPOSITORY=Emurgo/proof-tool\n"+
			"MPC_TAG=v4.5.6\n"+
			"MPC_SHA256=%s\n"+
			"REHEARSAL_ARCHIVE_SHA256=none\n",
		relayHash,
		mpcHash,
	)
	writeFixtureFile(t, filepath.Join(kit, "release.env"), []byte(releaseEnv), 0o644)
	releaseJSON := fmt.Sprintf(
		"{\n  \"schema\": \"ceremony-kit-v1\",\n  \"mode\": \"production\",\n"+
			"  \"relay\": {\n    \"repository\": \"zksecurity/relay\",\n    \"tag\": \"v1.2.3\",\n    \"sha256\": \"%s\"\n  },\n"+
			"  \"mpc_ceremony\": {\n    \"repository\": \"Emurgo/proof-tool\",\n    \"tag\": \"v4.5.6\",\n    \"sha256\": \"%s\"\n  },\n"+
			"  \"rehearsal_archive_sha256\": \"none\"\n}\n",
		relayHash,
		mpcHash,
	)
	writeFixtureFile(t, filepath.Join(kit, "release.json"), []byte(releaseJSON), 0o644)
	compatibility := fmt.Sprintf(
		"{\n  \"schema\": \"ceremony-kit-compatibility-v1\",\n  \"test\": \"tiny-rehearsal-phase1-contribution-v1\",\n"+
			"  \"relay_sha256\": \"%s\",\n  \"mpc_ceremony_sha256\": \"%s\"\n}\n",
		relayHash,
		mpcHash,
	)
	writeFixtureFile(t, filepath.Join(kit, "compatibility.json"), []byte(compatibility), 0o644)

	checksumNames := []string{
		"compatibility.json", "mpc-ceremony", "relay", "release.env",
		"release.json", "setup", "storage-setup.tar.gz",
	}
	var checksums strings.Builder
	for _, name := range checksumNames {
		fmt.Fprintf(&checksums, "%s  %s\n", fileSHA256ForTest(t, filepath.Join(kit, name)), name)
	}
	writeFixtureFile(t, filepath.Join(kit, "checksums.sha256"), []byte(checksums.String()), 0o644)

	receiptPath := filepath.Join(root, "tool-identity-receipt.env")
	command := exec.Command(filepath.Join(kit, "setup"), "verify", "--receipt-out", receiptPath)
	command.Dir = kit
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("setup verify: %v\n%s", err, output)
	}
	receipt, err := loadToolIdentityReceipt(receiptPath)
	if err != nil {
		t.Fatalf("load setup receipt: %v", err)
	}
	if receipt.Relay.ReleaseID != "zksecurity/relay@v1.2.3" ||
		receipt.MPCCeremony.ReleaseID != "Emurgo/proof-tool@v4.5.6" ||
		receipt.Relay.SHA256 != relayHash || receipt.MPCCeremony.SHA256 != mpcHash {
		t.Fatalf("setup receipt = %+v", receipt)
	}
	for _, want := range []string{toolIdentityReceiptSchema, receipt.Relay.ReleaseID, receipt.MPCCeremony.ReleaseID, receiptPath} {
		if !strings.Contains(string(output), want) {
			t.Errorf("setup output does not contain %q:\n%s", want, output)
		}
	}
	if info, err := os.Stat(receiptPath); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("receipt mode = %v, %v; want 0444", info, err)
	}
	secondCommand := exec.Command(filepath.Join(kit, "setup"), "verify", "--receipt-out", receiptPath)
	secondCommand.Dir = kit
	if secondOutput, err := secondCommand.CombinedOutput(); err == nil || !strings.Contains(string(secondOutput), "receipt output already exists") {
		t.Fatalf("setup replaced receipt: error=%v output=%s", err, secondOutput)
	}
}

func TestVerifyToolIdentitiesAuthenticatesResolvedExecutables(t *testing.T) {
	root := t.TempDir()
	mpcPath := filepath.Join(root, "mpc-ceremony")
	if err := os.WriteFile(mpcPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "tool-identity-receipt.env")
	writeTestToolIdentityReceipt(t, receiptPath, "production", mpcPath)

	verified, err := verifyToolIdentities(receiptPath, mpcPath)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Receipt.KitMode != "production" || verified.MPCCeremonyPath != verified.Receipt.MPCCeremony.VerifiedPath {
		t.Fatalf("verified identities = %+v", verified)
	}
	for _, want := range []string{
		"ceremony-kit-tool-identity-receipt-v1",
		"zksecurity/relay@test-release",
		"Emurgo/proof-tool@test-release",
		verified.RelayPath,
		verified.MPCCeremonyPath,
		verified.Receipt.Relay.SHA256,
		verified.Receipt.MPCCeremony.SHA256,
	} {
		if output := formatToolIdentityVerification(verified); !strings.Contains(output, want) {
			t.Fatalf("tool receipt output does not contain %q:\n%s", want, output)
		}
	}
}

func TestVerifyToolIdentitiesRejectsBinaryMismatch(t *testing.T) {
	root := t.TempDir()
	mpcPath := filepath.Join(root, "mpc-ceremony")
	if err := os.WriteFile(mpcPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "tool-identity-receipt.env")
	writeTestToolIdentityReceipt(t, receiptPath, "rehearsal", mpcPath)
	if err := os.WriteFile(mpcPath, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	_, err := verifyToolIdentities(receiptPath, mpcPath)
	if err == nil || !strings.Contains(err.Error(), "does not match approved release") {
		t.Fatalf("binary mismatch error = %v", err)
	}
}

func TestLoadToolIdentityReceiptRejectsDuplicateAndSymlink(t *testing.T) {
	root := t.TempDir()
	mpcPath := filepath.Join(root, "mpc-ceremony")
	if err := os.WriteFile(mpcPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "tool-identity-receipt.env")
	writeTestToolIdentityReceipt(t, receiptPath, "rehearsal", mpcPath)
	original, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	duplicatePath := filepath.Join(root, "duplicate.env")
	duplicate := append(append([]byte(nil), original...), []byte("KIT_MODE=rehearsal\n")...)
	if err := os.WriteFile(duplicatePath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadToolIdentityReceipt(duplicatePath); err == nil || !strings.Contains(err.Error(), "repeats KIT_MODE") {
		t.Fatalf("duplicate receipt error = %v", err)
	}

	symlinkPath := filepath.Join(root, "receipt-link.env")
	if err := os.Symlink(receiptPath, symlinkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := loadToolIdentityReceipt(symlinkPath); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink receipt error = %v", err)
	}
}

func writeTestToolIdentityReceipt(t *testing.T, path, mode, mpcPath string) {
	t.Helper()
	relayExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	relayPath, relayHash, err := resolveAndHashExecutable(relayExecutable)
	if err != nil {
		t.Fatal(err)
	}
	mpcResolved, mpcHash, err := resolveAndHashExecutable(mpcPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt := fmt.Sprintf(
		"TOOL_IDENTITY_RECEIPT_SCHEMA=%s\n"+
			"KIT_MODE=%s\n"+
			"KIT_ROOT=%s\n"+
			"COMPATIBILITY_TEST=tiny-rehearsal-phase1-contribution-v1\n"+
			"RELAY_VERIFIED_PATH=%s\n"+
			"RELAY_REPOSITORY=zksecurity/relay\n"+
			"RELAY_VERSION=test-release\n"+
			"RELAY_RELEASE_ID=zksecurity/relay@test-release\n"+
			"RELAY_SHA256=%s\n"+
			"MPC_CEREMONY_VERIFIED_PATH=%s\n"+
			"MPC_CEREMONY_REPOSITORY=Emurgo/proof-tool\n"+
			"MPC_CEREMONY_VERSION=test-release\n"+
			"MPC_CEREMONY_RELEASE_ID=Emurgo/proof-tool@test-release\n"+
			"MPC_CEREMONY_SHA256=%s\n",
		toolIdentityReceiptSchema,
		mode,
		filepath.Clean(filepath.Dir(path)),
		relayPath,
		relayHash,
		mpcResolved,
		mpcHash,
	)
	if err := os.WriteFile(path, []byte(receipt), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFixtureFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
}

func fileSHA256ForTest(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
