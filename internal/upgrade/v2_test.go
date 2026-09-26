package upgrade

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixtureV2() DeclarationV2 {
	a := strings.Repeat("a", 40)
	return DeclarationV2{Schema: SchemaV2, OriginalRelease: a, SourceApp: a, TargetApp: strings.Repeat("b", 40), Role: "coordinator", Host: "darwin/arm64", Platform: "linux/arm64", OriginalImage: "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + strings.Repeat("c", 64), SigningImage: "ghcr.io/zksecurity/relay/relay-role-offline@sha256:" + strings.Repeat("d", 64), OnlineImage: "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + strings.Repeat("e", 64), ProofToolSHA256: "sha256:" + strings.Repeat("f", 64), QualificationSHA256: "sha256:" + strings.Repeat("1", 64), Protocol: "proof-tool-mpc-ceremony-definition-v4", StorageLayout: "storage-first-v2", ProfileSchema: "relay-guided-role-v1", JournalSchema: "relay-workflow-v4-state-v1", Adapters: []string{"inspect-v1", "checkpoint-cas-v4-v1"}, SafePredecessors: []string{a}}
}

func TestV5CoordinatorUpgradePreservesProtocolBoundary(t *testing.T) {
	d := fixtureV2()
	d.Protocol = "proof-tool-mpc-ceremony-definition-v5"
	if err := d.Validate(); err != nil {
		t.Fatalf("V5 coordinator upgrade rejected: %v", err)
	}
	d.Role = "auditor"
	if err := d.Validate(); err == nil {
		t.Fatal("V5 non-coordinator upgrade accepted without a qualified role journey")
	}
}

func TestV5ReleaseSignerUpgradeKeepsOriginalRuntime(t *testing.T) {
	d := fixtureV2()
	d.Role = "release-signer"
	d.Protocol = "proof-tool-mpc-ceremony-definition-v5"
	d.OriginalImage = d.SigningImage
	d.OnlineImage = ""
	d.Schema = OperatorTransitionSchema
	d.QualificationSHA256 = ""
	d.SafePredecessors = nil
	if err := d.Validate(); err != nil {
		t.Fatalf("V5 signer upgrade rejected: %v", err)
	}
	d.OnlineImage = fixtureV2().OnlineImage
	if err := d.Validate(); err == nil {
		t.Fatal("signer upgrade changed the network-disabled runtime")
	}
}

func TestV2RejectsUnsupportedAndAmbiguousAuthority(t *testing.T) {
	d := fixtureV2()
	raw, _ := json.Marshal(d)
	if _, err := DecodeV2(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(append([]byte{}, raw...), raw...), []byte(strings.Replace(string(raw), `"role":"coordinator"`, `"role":"auditor","role":"coordinator"`, 1)), []byte(strings.Replace(string(raw), `"role":"coordinator"`, `"role":"coordinator","new":true`, 1))} {
		if _, err := DecodeV2(bad); err == nil {
			t.Fatal("accepted ambiguous authority")
		}
	}
	for _, change := range []func(*DeclarationV2){func(d *DeclarationV2) { d.StorageLayout = "unknown" }, func(d *DeclarationV2) { d.Adapters = []string{"magic"} }, func(d *DeclarationV2) { d.SafePredecessors = nil }, func(d *DeclarationV2) { d.Role = "participant" }, func(d *DeclarationV2) { d.OriginalImage = "mutable:tag" }, func(d *DeclarationV2) { d.Host = "windows/amd64" }} {
		bad := d
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("accepted unsupported authority", bad)
		}
	}
}

func TestV2InheritedCoverageIsNotTransitive(t *testing.T) {
	d := fixtureV2()
	d.SourceApp = strings.Repeat("b", 40)
	d.TargetApp = strings.Repeat("c", 40)
	d.SafePredecessors = append(d.SafePredecessors, d.SourceApp)
	if err := d.Cover([]string{d.OriginalRelease, d.SourceApp}, []string{"inspect", "checkpoint"}); err != nil {
		t.Fatal(err)
	}
	if d.Cover([]string{strings.Repeat("d", 40)}, nil) == nil {
		t.Fatal("lost inherited runtime")
	}
	if d.Cover(nil, []string{"contribute"}) == nil {
		t.Fatal("missing recovery coverage")
	}
}

func TestV2QualificationIsExact(t *testing.T) {
	d := fixtureV2()
	q := QualificationV2{Schema: "relay-upgrade-qualification/v2", OriginalRelease: d.OriginalRelease, SourceApp: d.SourceApp, TargetApp: d.TargetApp, Role: d.Role, Host: d.Host, Platform: d.Platform, OnlineImage: d.OnlineImage, ProofToolSHA256: d.ProofToolSHA256, LauncherSHA256: "sha256:" + strings.Repeat("3", 64), Passed: append([]string{}, QualificationChecks...)}
	q.OriginalImage, q.SigningImage = d.OriginalImage, d.SigningImage
	q.Predecessors = map[string]string{d.OriginalRelease: "sha256:" + strings.Repeat("4", 64)}
	raw, _ := json.Marshal(q)
	if _, err := VerifyQualification(raw, d); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*QualificationV2){func(q *QualificationV2) { q.Role = "auditor" }, func(q *QualificationV2) { q.Passed = q.Passed[:len(q.Passed)-1] }, func(q *QualificationV2) { q.LauncherSHA256 = "" }, func(q *QualificationV2) { q.SourceApp = q.TargetApp }, func(q *QualificationV2) { q.Predecessors = nil }, func(q *QualificationV2) { q.SigningImage = q.OriginalImage }, func(q *QualificationV2) { q.Passed = append(append([]string{}, q.Passed...), "made-up") }} {
		bad := q
		change(&bad)
		raw, _ := json.Marshal(bad)
		if _, err := VerifyQualification(raw, d); err == nil {
			t.Fatal("accepted wrong or incomplete qualification")
		}
	}
}
