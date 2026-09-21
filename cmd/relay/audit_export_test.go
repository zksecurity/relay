package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func auditTestDir(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
func auditTestReport() auditReport {
	return auditReport{Schema: auditReportSchema, CeremonyID: strings.Repeat("a", 64), DefinitionSHA256: strings.Repeat("b", 64), Sources: []auditSource{{ID: strings.Repeat("c", 64), Role: "participant", Observations: []auditObservation{{ID: strings.Repeat("d", 64), Action: "contribute", Status: "running", Prepared: time.Now().UTC().Format(time.RFC3339Nano)}}}}, Coverage: auditCoverage()}
}
func TestAuditExportSanitizesImportedCanaries(t *testing.T) {
	r := auditTestReport()
	canary := "SECRET /home/operator/key --token=secret"
	r.Sources[0].Role = canary
	r.Sources[0].Observations[0].Action = canary
	r.Sources[0].Observations[0].Prepared = canary
	r.Sources[0].Observations[0].Status = canary
	r.Sources[0].Events = []diagnosticEvent{{Time: canary, Role: canary, Stage: canary, Action: canary, Outcome: canary, ErrorCode: canary, Release: canary}}
	r.Coverage = []string{canary}
	out := filepath.Join(auditTestDir(t), "out")
	if e := writeAuditReport(out, r); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"report.json", "report.md"} {
		raw, e := os.ReadFile(filepath.Join(out, name))
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(raw), "SECRET") || strings.Contains(string(raw), "/home/operator") {
			t.Fatalf("private value in %s", name)
		}
	}
}
func TestAuditCombineMatchingDedupAndConflict(t *testing.T) {
	base := auditTestDir(t)
	r := auditTestReport()
	one := filepath.Join(base, "one")
	two := filepath.Join(base, "two")
	if e := writeAuditReport(one, r); e != nil {
		t.Fatal(e)
	}
	r.Sources[0].Observations[0].Status = "reconciled"
	if e := writeAuditReport(two, r); e != nil {
		t.Fatal(e)
	}
	combined, e := combineAuditExports([]string{one, one, two})
	if e != nil {
		t.Fatal(e)
	}
	if len(combined.Sources) != 2 || len(combined.Conflicts) != 1 {
		t.Fatalf("unexpected sources/conflicts: %+v", combined)
	}
	if combined.Sources[0].ReportSHA256 == combined.Sources[1].ReportSHA256 {
		t.Fatal("lost provenance")
	}
	r.CeremonyID = strings.Repeat("e", 64)
	three := filepath.Join(base, "three")
	if e = writeAuditReport(three, r); e != nil {
		t.Fatal(e)
	}
	if _, e = combineAuditExports([]string{one, three}); e == nil {
		t.Fatal("mixed ceremonies accepted")
	}
}
func TestAuditStrictInputAndFreshOutput(t *testing.T) {
	base := auditTestDir(t)
	out := filepath.Join(base, "out")
	if e := writeAuditReport(out, auditTestReport()); e != nil {
		t.Fatal(e)
	}
	if e := writeAuditReport(out, auditTestReport()); e == nil {
		t.Fatal("overwrote output")
	}
	link := filepath.Join(base, "link")
	if e := os.Symlink(out, link); e != nil {
		t.Fatal(e)
	}
	if _, e := combineAuditExports([]string{link}); e == nil {
		t.Fatal("symlink input accepted")
	}
	for _, raw := range []string{`{"schema":"a","schema":"b"}`, `{"unexpected":"secret"}`, `{} {}`} {
		if e := os.WriteFile(filepath.Join(out, "report.json"), []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := combineAuditExports([]string{out}); e == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}
func TestAuditExportJournalCanariesAndBusyWorkspace(t *testing.T) {
	work := auditTestDir(t)
	if e := os.Mkdir(filepath.Join(work, "workflow-v4"), 0700); e != nil {
		t.Fatal(e)
	}
	s := workflowV4State{Schema: workflowV4JournalSchema, Marker: workflowV4Marker{Schema: workflowV4MarkerSchema, WorkspaceID: "workspace-private"}}
	s.Marker.Binding.CeremonyID = "sha256:" + strings.Repeat("a", 64)
	s.Marker.Binding.Definition.Record.Digest.SHA256 = "sha256:" + strings.Repeat("b", 64)
	s.Marker.Binding.Role = "participant"
	s.Marker.Binding.IdentityID = "SECRET_IDENTITY"
	s.Marker.Binding.Work = "/SECRET/path"
	s.Operations = []workflowV4Operation{{Plan: workflowV4OperationPlan{ID: "SECRET_OPERATION", Kind: "contribute", Command: []string{"SECRET_COMMAND"}, Outputs: []string{"/SECRET_OUTPUT"}}, Status: "running", Prepared: time.Now()}}
	raw, _ := json.Marshal(s)
	if e := os.WriteFile(filepath.Join(work, "workflow-v4", "state.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	report, e := buildAuditExport(work)
	if e != nil {
		t.Fatal(e)
	}
	exported, _ := json.Marshal(report)
	if strings.Contains(string(exported), "SECRET") {
		t.Fatal("journal canary leaked")
	}
	lock, e := acquireParticipantRunLock("", work)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.release()
	if _, e = buildAuditExport(work); e == nil {
		t.Fatal("busy workspace exported")
	}
}
func TestAuditCombineVerificationRemainsExporterClaim(t *testing.T) {
	r := auditTestReport()
	r.Verification = &auditVerification{Status: "passed", Depth: "checkpoint-structure", MathematicsReplayed: true, GlobalFreshnessVerified: true}
	out := filepath.Join(auditTestDir(t), "out")
	if e := writeAuditReport(out, r); e != nil {
		t.Fatal(e)
	}
	combined, e := combineAuditExports([]string{out})
	if e != nil {
		t.Fatal(e)
	}
	if combined.Verification != nil || combined.Sources[0].ExporterClaims == nil || combined.Sources[0].ExporterClaims.Status != "exporter-reported" || combined.Sources[0].ExporterClaims.MathematicsReplayed || combined.Sources[0].ExporterClaims.GlobalFreshnessVerified {
		t.Fatal("import upgraded authentication")
	}
}

func TestAuditRejectsOversizedInputAndIdentityCanary(t *testing.T) {
	base := auditTestDir(t)
	p := filepath.Join(base, "report.json")
	f, e := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(auditReadLimit + 1); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e = combineAuditExports([]string{base}); e == nil {
		t.Fatal("oversized report accepted")
	}
	r := auditTestReport()
	r.Sources[0].ID = "SECRET_IDENTITY"
	if e = writeAuditReport(filepath.Join(base, "out"), r); e == nil {
		t.Fatal("unvalidated identity accepted")
	}
}

func TestAuditExportPreservesOnlyFixedCoverageAndConflicts(t *testing.T) {
	r := auditTestReport()
	r.Sources[0].Gaps = []string{"partial-final-record", "SECRET_PATH", "activity-log-missing"}
	r.Conflicts = []string{"SECRET_CONFLICT", "Different snapshots supplied for source " + strings.Repeat("c", 64)}
	r.Verification = &auditVerification{Status: "SECRET_STATUS", Progress: []string{"SECRET_PROGRESS"}}
	out := filepath.Join(auditTestDir(t), "out")
	if e := writeAuditReport(out, r); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(out, "report.json"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), "SECRET") {
		t.Fatal("non-allowlisted report text leaked")
	}
	var parsed auditReport
	if e = json.Unmarshal(raw, &parsed); e != nil {
		t.Fatal(e)
	}
	if len(parsed.Sources[0].Gaps) != 2 || len(parsed.Conflicts) != 1 {
		t.Fatal("fixed coverage/conflict lost")
	}
	combined, e := combineAuditExports([]string{out})
	if e != nil {
		t.Fatal(e)
	}
	if len(combined.Sources[0].Gaps) != 2 {
		t.Fatal("combine lost gaps")
	}
}
func TestAuditEventDedupKeyIgnoresOnlyCorrelation(t *testing.T) {
	a := diagnosticEvent{Time: time.Now().UTC().Format(time.RFC3339Nano), Role: "participant", Stage: "launcher", Action: "open-guide", Outcome: "started"}
	b := a
	b.Sequence = 1
	b.OperationID = strings.Repeat("a", 32)
	if auditEventKey(a) != auditEventKey(b) {
		t.Fatal("legacy/durable copies differ")
	}
	b.Outcome = "succeeded"
	if auditEventKey(a) == auditEventKey(b) {
		t.Fatal("distinct outcomes deduped")
	}
}
