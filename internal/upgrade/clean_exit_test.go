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
