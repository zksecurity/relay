package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditVerificationRequiresExplicitTrustAndCheckpoint(t *testing.T) {
	for _, args := range [][]string{{"export", "--work", "/unused", "--out", "/unused-out", "--mpc-ceremony", "/tool"}, {"export", "--work", "/unused", "--out", "/unused-out", "--checkpoint", "head.json"}, {"export", "--work", "/unused", "--out", "/unused-out", "--coordinator-key-file", "/key"}, {"combine", "--out", "/unused-out"}} {
		if err := runAudit(args); err == nil {
			t.Fatal("incomplete audit arguments accepted")
		}
	}
}
func TestAuditVerificationRejectsUnsafeCheckpointPaths(t *testing.T) {
	root := auditTestDir(t)
	for _, path := range []string{"../key", "/key", ".", "a/../key", `a\key`} {
		if _, err := auditPublicPath(root, path); err == nil {
			t.Fatal("unsafe checkpoint accepted", path)
		}
	}
	if err := os.Symlink(root, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := auditPublicPath(root, "link"); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestAuditVerificationFailureNeverClaimsSuccess(t *testing.T) {
	work := auditTestDir(t)
	key := filepath.Join(work, "coordinator.hex")
	if err := os.WriteFile(key, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := verifyAuditCheckpoint(context.Background(), work, key, "/missing-tool", "checkpoint.json", "checkpoint.sig", auditTestReport())
	if err == nil || v == nil || v.Status != "failed" || v.Depth != "not-run" || v.MathematicsReplayed || v.GlobalFreshnessVerified {
		t.Fatal("failed auth not explicit", v, err)
	}
}
func TestAuditImportedVerificationCannotUpgradeEvidence(t *testing.T) {
	v := auditExporterClaim(&auditVerification{Status: "passed", Depth: "checkpoint-structure", MathematicsReplayed: true, GlobalFreshnessVerified: true, Progress: []string{"SECRET", "final-release"}, CoordinatorKeySHA256: "SECRET"})
	if v.Status != "exporter-reported" || v.MathematicsReplayed || v.GlobalFreshnessVerified || v.CoordinatorKeySHA256 != "" || len(v.Progress) != 1 {
		t.Fatal("imported claims escaped boundary", v)
	}
}
