package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
