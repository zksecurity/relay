package upgrade

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCleanExitQualificationIsSeparateAndExact(t *testing.T) {
	d := fixtureV2()
	d.OnlineImage = d.OriginalImage
	q := QualificationV2{Schema: CleanExitQualificationSchema, OriginalRelease: d.OriginalRelease, SourceApp: d.SourceApp, TargetApp: d.TargetApp, Role: d.Role, Host: d.Host, Platform: d.Platform, LauncherSHA256: "sha256:" + strings.Repeat("1", 64), OnlineImage: d.OnlineImage, OriginalImage: d.OriginalImage, SigningImage: d.SigningImage, ProofToolSHA256: d.ProofToolSHA256, Predecessors: map[string]string{d.OriginalRelease: "sha256:" + strings.Repeat("2", 64)}, Passed: append([]string{}, CleanExitQualificationChecks...)}
	raw, _ := json.Marshal(q)
	if _, err := VerifyQualification(raw, d); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*QualificationV2){func(q *QualificationV2) { q.Schema = "relay-upgrade-qualification/v2" }, func(q *QualificationV2) { q.Passed = QualificationChecks }, func(q *QualificationV2) { q.Passed = q.Passed[:2] }, func(q *QualificationV2) {
		q.OnlineImage = "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + strings.Repeat("3", 64)
	}} {
		bad := q
		change(&bad)
		b, _ := json.Marshal(bad)
		if _, err := VerifyQualification(b, d); err == nil {
			t.Fatal("accepted mixed qualification scope")
		}
	}
	d.Role = "auditor"
	q.Role = d.Role
	raw, _ = json.Marshal(q)
	if _, err := VerifyQualification(raw, d); err == nil {
		t.Fatal("accepted unsupported role")
	}
}

func TestOnlineQualificationRequiresItsOwnCompleteEvidence(t *testing.T) {
	d := fixtureV2()
	if d.OnlineImage == d.OriginalImage {
		t.Fatal("fixture must replace online image")
	}
	q := QualificationV2{Schema: OnlineCleanExitQualificationSchema, OriginalRelease: d.OriginalRelease, SourceApp: d.SourceApp, TargetApp: d.TargetApp, Role: d.Role, Host: d.Host, Platform: d.Platform, LauncherSHA256: "sha256:" + strings.Repeat("1", 64), OnlineImage: d.OnlineImage, OriginalImage: d.OriginalImage, SigningImage: d.SigningImage, ProofToolSHA256: d.ProofToolSHA256, Predecessors: map[string]string{d.OriginalRelease: "sha256:" + strings.Repeat("2", 64)}, Passed: append([]string{}, OnlineCleanExitQualificationChecks...)}
	raw, _ := json.Marshal(q)
	if _, err := VerifyQualification(raw, d); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*QualificationV2){
		"native evidence":      func(q *QualificationV2) { q.Schema = CleanExitQualificationSchema },
		"missing online tests": func(q *QualificationV2) { q.Passed = CleanExitQualificationChecks },
		"missing reentry":      func(q *QualificationV2) { q.Passed = q.Passed[:4] },
		"changed proof":        func(q *QualificationV2) { q.ProofToolSHA256 = "sha256:" + strings.Repeat("9", 64) },
		"changed signer":       func(q *QualificationV2) { q.SigningImage = q.OriginalImage },
	} {
		t.Run(name, func(t *testing.T) {
			bad := q
			change(&bad)
			raw, _ := json.Marshal(bad)
			if _, err := VerifyQualification(raw, d); err == nil {
				t.Fatal("accepted mismatched online evidence")
			}
		})
	}
	d.OnlineImage = d.OriginalImage
	q.OnlineImage = d.OnlineImage
	raw, _ = json.Marshal(q)
	if _, err := VerifyQualification(raw, d); err == nil {
		t.Fatal("accepted native update as online qualification")
	}
}
