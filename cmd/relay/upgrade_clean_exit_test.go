package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
	"github.com/zksecurity/relay/internal/upgrade"
)

func TestCleanExitPublicKeyFormatting(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "public.hex"), filepath.Join(dir, "trusted.hex")
	for _, tc := range []struct {
		value string
		same  bool
	}{
		{strings.Repeat("ab", 32) + "\n", true},
		{strings.Repeat("AB", 32), true},
		{strings.Repeat("cd", 32), false},
		{"invalid", false},
	} {
		if err := os.WriteFile(a, []byte(tc.value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(b, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
			t.Fatal(err)
		}
		if upgradeSamePublicKey(a, b) != tc.same {
			t.Fatalf("incorrect key comparison for %q", tc.value)
		}
	}
}

func TestUpgradeOnlyPendingSignerEnrollmentImport(t *testing.T) {
	start := diagnosticEvent{OperationID: "one", Outcome: "started", Role: "coordinator", Stage: "workflow-v4", Action: "import-signer-enrollment"}
	for _, tc := range []struct {
		name   string
		events []diagnosticEvent
		allow  bool
	}{
		{"one pending signer import", []diagnosticEvent{start}, true},
		{"unrelated completed action", []diagnosticEvent{{OperationID: "old", Outcome: "started"}, {OperationID: "old", Outcome: "succeeded"}, start}, true},
		{"no pending import", []diagnosticEvent{start, {OperationID: "one", Outcome: "succeeded"}}, false},
		{"other pending action", []diagnosticEvent{start, {OperationID: "two", Outcome: "started", Action: "coordinator-action"}}, false},
		{"wrong role", []diagnosticEvent{{OperationID: "one", Outcome: "started", Role: "participant", Stage: start.Stage, Action: start.Action}}, false},
		{"wrong stage", []diagnosticEvent{{OperationID: "one", Outcome: "started", Role: start.Role, Stage: "setup", Action: start.Action}}, false},
		{"wrong action", []diagnosticEvent{{OperationID: "one", Outcome: "started", Role: start.Role, Stage: start.Stage, Action: "enrollment"}}, false},
		{"reused identifier", []diagnosticEvent{start, start}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := upgradeOnlyPendingSignerEnrollmentImport(tc.events); got != tc.allow {
				t.Fatalf("allow=%v, want %v", got, tc.allow)
			}
		})
	}
}

func TestUpgradeMatchCommittedSignerEnrollment(t *testing.T) {
	protocol, _ := workflowV4TestBinding(t)
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil {
		t.Fatal(err)
	}
	metadata := transcript.EnrollmentMetadataInspectionV4{}
	metadata.Metadata.Enrollments = []transcript.CommittedEnrollmentMetadataV4{{
		Refs: transcript.SignedArtifactRefs{
			Record:    transcript.ArtifactRef{Name: filepath.Join("enrollments", expected.Identity.ID, "enrollment.json")},
			Signature: transcript.ArtifactRef{Name: filepath.Join("enrollments", expected.Identity.ID, "enrollment.sig")},
		},
		Enrollment: transcript.EnrollmentInspection{Role: expected.Role, RoleIndex: expected.RoleIndex, Identity: expected.Identity},
	}}
	if _, err := upgradeMatchCommittedSignerEnrollment(protocol, metadata); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name string
		edit func(*transcript.EnrollmentInspection)
	}{
		{"wrong identity", func(e *transcript.EnrollmentInspection) { e.Identity.ID = "other" }},
		{"wrong key", func(e *transcript.EnrollmentInspection) { e.Identity.KeyID = "other" }},
		{"wrong role", func(e *transcript.EnrollmentInspection) { e.Role = "participant" }},
		{"wrong index", func(e *transcript.EnrollmentInspection) { e.RoleIndex++ }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			wrong := metadata
			wrong.Metadata.Enrollments = append([]transcript.CommittedEnrollmentMetadataV4(nil), metadata.Metadata.Enrollments...)
			mutate.edit(&wrong.Metadata.Enrollments[0].Enrollment)
			if _, err := upgradeMatchCommittedSignerEnrollment(protocol, wrong); err == nil {
				t.Fatal("accepted a different signed enrollment")
			}
		})
	}
}

func TestUpgradeCheckSignerImportStaging(t *testing.T) {
	id := "release-signer-test"
	public := upgradeInventoryFile{Name: "ceremony/public/enrollments/" + id + "/enrollment.json", SHA256: "accepted", Size: 9}
	staged := upgradeInventoryFile{Name: "workflow-v4/staging/enrollment-" + id + "-123/artifacts/enrollments/" + id + "/enrollment.json", SHA256: public.SHA256, Size: public.Size}
	if err := upgradeCheckSignerImportStaging(upgradeInventory{Files: []upgradeInventoryFile{public, staged}}, id); err != nil {
		t.Fatal("rejected retained exact staging copy", err)
	}
	for _, bad := range []upgradeInventoryFile{
		{Name: staged.Name, SHA256: "uncommitted", Size: staged.Size},
		{Name: staged.Name, SHA256: staged.SHA256, Size: staged.Size + 1},
		{Name: "workflow-v4/staging/enrollment-" + id + "-123/other.json", SHA256: staged.SHA256, Size: staged.Size},
	} {
		if err := upgradeCheckSignerImportStaging(upgradeInventory{Files: []upgradeInventoryFile{public, bad}}, id); err == nil {
			t.Fatalf("accepted conflicting signer staging file %s", bad.Name)
		}
	}
}

func TestCleanExitRefusesMissingEvidenceWithoutSelecting(t *testing.T) {
	for _, schema := range []string{upgrade.CleanExitQualificationSchema, upgrade.OnlineCleanExitQualificationSchema} {
		t.Run(schema, func(t *testing.T) { testCleanExitRefusesMissingEvidence(t, schema) })
	}
}
func testCleanExitRefusesMissingEvidence(t *testing.T, schema string) {
	s, d := testUpgradeV2(t, "coordinator")
	if schema == upgrade.CleanExitQualificationSchema {
		d.OnlineImage = d.OriginalImage
	}
	testUpgradeV2Report(t, &s, &d)
	var q upgrade.QualificationV2
	if err := json.Unmarshal(s.Qualification, &q); err != nil {
		t.Fatal(err)
	}
	q.Schema = schema
	q.Passed = append([]string{}, upgrade.CleanExitQualificationChecks...)
	if schema == upgrade.OnlineCleanExitQualificationSchema {
		q.Passed = append([]string{}, upgrade.OnlineCleanExitQualificationChecks...)
	}
	s.Qualification, _ = json.Marshal(q)
	d.QualificationSHA256 = "sha256:" + upgradeBytesHash(s.Qualification)
	s.Declaration, _ = json.Marshal(d)
	before, _ := os.ReadFile(s.StartPath)
	if err := upgradeV2Activate(s, ""); err == nil {
		t.Fatal("admitted update without finished ceremony evidence")
	}
	after, _ := os.ReadFile(s.StartPath)
	if string(before) != string(after) {
		t.Fatal("changed old launcher on refusal")
	}
	if _, err := os.Stat(upgradeV2PointerPath(s.Profile.Work)); !os.IsNotExist(err) {
		t.Fatal("selected refused update")
	}
}

func TestCleanExitRejectsUnacceptedPublicOutput(t *testing.T) {
	s, _ := testUpgradeV2(t, "coordinator")
	inv := upgradeInventory{Files: []upgradeInventoryFile{{Name: "ceremony/public/checkpoints/phase1/partial/checkpoint.json", SHA256: "unused", Size: 10}}}
	if err := upgradeCheckCleanFiles(s.Profile, inv, nil, nil); err == nil {
		t.Fatal("accepted unpublished checkpoint")
	}
	if err := upgradeCheckCleanFiles(s.Profile, upgradeInventory{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	// A fully signed earlier intent remains on disk after completion. Only
	// accepted ancestry may clear it, not mere existence of the output file.
	out := filepath.Join(s.Profile.Work, "ceremony/public/checkpoints/old")
	intent := workflowV4CoordinatorIntent{Schema: workflowV4CoordinatorIntentSchema, Action: "allocate", OutputDir: out}
	file := filepath.Join(s.Profile.Work, "workflow-v4/coordinator/old-intent.json")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(intent)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	inv = upgradeInventory{Files: []upgradeInventoryFile{{Name: "workflow-v4/coordinator/old-intent.json"}}}
	if err := upgradeCheckCleanFiles(s.Profile, inv, nil, nil); err == nil {
		t.Fatal("cleared intent without ancestry")
	}
	child := transcript.CheckpointInspectionV4{}
	child.Checkpoint.PreviousCheckpoint = &intent.Predecessor
	child.Checkpoint.Deliveries = []transcript.DeliverySlotV4{{Scope: intent.Scope, AttemptID: intent.AttemptID, Kind: "candidate", Status: "allocated"}}
	if err := upgradeCheckCleanFiles(s.Profile, inv, map[string]transcript.CheckpointInspectionV4{"checkpoints/old/checkpoint.json": child}, nil); err != nil {
		t.Fatal("blocked completed historical intent", err)
	}
}

func TestUpgradeCompletedPreliminaryRequiresAcceptedKeys(t *testing.T) {
	const prefix = "ceremony/public/final/preliminary/"
	keys := []string{"ownership-destination.ccs", "ownership.pk", "ownership.vk", "cardano-vk.bin", "cardano-vk.hex", "cardano-vk-format.txt"}
	other := []string{"preliminary-final-keys.json", "preliminary-final-keys.sig.json", "preliminary-checksums.sha256"}
	var inv upgradeInventory
	public := map[string]transcript.ArtifactRef{}
	for _, name := range keys {
		inv.Files = append(inv.Files, upgradeInventoryFile{Name: prefix + name, SHA256: strings.Repeat("a", 64), Size: 7})
		public["final/candidate/"+name] = transcript.ArtifactRef{Name: "final/candidate/" + name, Digest: transcript.Digest{SHA256: "sha256:" + strings.Repeat("a", 64), Size: 7}}
	}
	for _, name := range other {
		inv.Files = append(inv.Files, upgradeInventoryFile{Name: prefix + name, SHA256: strings.Repeat("b", 64), Size: 7})
	}
	inv.Files = append(inv.Files, upgradeInventoryFile{Name: "ceremony/public/final/public-finalization-evidence.json", SHA256: strings.Repeat("d", 64), Size: 7})
	public["final/candidate/public-finalization-evidence.json"] = transcript.ArtifactRef{Name: "final/candidate/public-finalization-evidence.json", Digest: transcript.Digest{SHA256: "sha256:" + strings.Repeat("d", 64), Size: 7}}
	if allowed, err := upgradeCompletedPreliminaryFiles(inv, public); err != nil || len(allowed) != 10 {
		t.Fatalf("completed accepted tree refused: %d %v", len(allowed), err)
	}
	wrong := public["final/candidate/ownership.pk"]
	wrong.Digest.SHA256 = "sha256:" + strings.Repeat("c", 64)
	public["final/candidate/ownership.pk"] = wrong
	if _, err := upgradeCompletedPreliminaryFiles(inv, public); err == nil {
		t.Fatal("changed key matched accepted final candidate")
	}
	public["final/candidate/ownership.pk"] = transcript.ArtifactRef{Name: "final/candidate/ownership.pk", Digest: transcript.Digest{SHA256: "sha256:" + strings.Repeat("a", 64), Size: 7}}
	inv.Files = append(inv.Files, upgradeInventoryFile{Name: prefix + "extra", SHA256: strings.Repeat("a", 64), Size: 7})
	if _, err := upgradeCompletedPreliminaryFiles(inv, public); err == nil {
		t.Fatal("unexpected preliminary file admitted")
	}
}

func TestCleanExitRejectsRetainedReleaseHandoff(t *testing.T) {
	p := guidedProfile{Work: t.TempDir()}
	inv := upgradeInventory{Files: []upgradeInventoryFile{{Name: "workflow-v4/coordinator/release/grants/release.json"}}}
	if err := upgradeCheckCleanFiles(p, inv, nil, nil); err == nil {
		t.Fatal("accepted an unresolved release handoff")
	}
}

func TestReleaseSignerUpgradeRequiresCompletedLocalWork(t *testing.T) {
	s, d := testUpgradeV2(t, "release-signer")
	d.Schema = upgrade.OperatorTransitionSchema
	d.Protocol = "proof-tool-mpc-ceremony-definition-v5"
	d.QualificationSHA256 = ""
	d.SafePredecessors = nil
	if err := upgradeRequireSignerCleanExit(s.Profile, d); err == nil {
		t.Fatal("accepted signer workspace without a journal")
	}
	protocol, binding := workflowV4TestBinding(t)
	binding.Name = s.Profile.Name
	binding.Role = "release-signer"
	binding.IdentityID = "release-signer-test"
	binding.Work = s.Profile.Work
	for kind, runtime := range binding.Runtimes {
		runtime.Mounts["/work"] = s.Profile.Work
		binding.Runtimes[kind] = runtime
	}
	j, err := openWorkflowV4Journal(protocol, protocol.DefinitionRefs, binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	if err := upgradeRequireSignerCleanExit(s.Profile, d); err == nil {
		t.Fatal("accepted signer workspace without a completed activity log")
	}
	if err := appendAuditActivity(diagnosticContext{Work: s.Profile.Work, Role: "release-signer"}, "completed", nil, "setup"); err != nil {
		t.Fatal(err)
	}
	if err := upgradeRequireSignerCleanExit(s.Profile, d); err != nil {
		t.Fatalf("rejected normally closed signer workspace: %v", err)
	}
	imported := filepath.Join(s.Profile.Work, "incoming-definition")
	if err := os.Mkdir(imported, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(imported, "ceremony.json"), []byte("public handoff"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := upgradeRequireSignerCleanExit(s.Profile, d); err != nil {
		t.Fatalf("rejected inventoried public signer handoff: %v", err)
	}
	if err := appendAuditActivity(diagnosticContext{Work: s.Profile.Work, Role: "release-signer"}, "started", nil, strings.Repeat("1", 32)); err != nil {
		t.Fatal(err)
	}
	if err := upgradeRequireSignerCleanExit(s.Profile, d); err == nil {
		t.Fatal("accepted unfinished signer activity")
	}
}
