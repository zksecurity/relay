package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func activityTestContext(t *testing.T) diagnosticContext {
	t.Helper()
	return diagnosticContext{Work: t.TempDir(), Role: "participant", Release: "private-canary", Stage: "workflow-v4", Action: "participant-action"}
}
func TestAuditActivityRetainsHistoryAndCorrelates(t *testing.T) {
	c := activityTestContext(t)
	for i := 0; i < 110; i++ {
		finish, err := beginAuditActivity(c)
		if err != nil {
			t.Fatal(err)
		}
		finish(nil, nil)
	}
	events, gaps, err := readAuditActivity(c.Work)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 220 {
		t.Fatalf("retained %d", len(events))
	}
	for i := 0; i < len(events); i += 2 {
		if events[i].Sequence != uint64(i+1) || events[i].OperationID == "" || events[i].OperationID != events[i+1].OperationID {
			t.Fatal("correlation lost")
		}
	}
	if strings.Contains(strings.Join(gaps, ","), "completion") {
		t.Fatal(gaps)
	}
	raw, err := os.ReadFile(filepath.Join(c.Work, diagnosticDirectory, auditActivityFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("private-canary")) {
		t.Fatal("private release leaked")
	}
}
func TestAuditActivityInterruptedAndPartial(t *testing.T) {
	c := activityTestContext(t)
	if _, err := beginAuditActivity(c); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Work, diagnosticDirectory, auditActivityFile)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"private":"canary`)
	f.Close()
	events, gaps, err := readAuditActivity(c.Work)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || !strings.Contains(strings.Join(gaps, ","), "partial-final-record") || !strings.Contains(strings.Join(gaps, ","), "actions-without-recorded-completion") {
		t.Fatal(events, gaps)
	}
	if _, err := beginAuditActivity(c); err == nil {
		t.Fatal("started through partial record")
	}
}
func TestAuditActivityRejectsEditedAndLinkedFiles(t *testing.T) {
	for _, mode := range []string{"edited", "link"} {
		t.Run(mode, func(t *testing.T) {
			c := activityTestContext(t)
			finish, err := beginAuditActivity(c)
			if err != nil {
				t.Fatal(err)
			}
			finish(nil, nil)
			path := filepath.Join(c.Work, diagnosticDirectory, auditActivityFile)
			raw, _ := os.ReadFile(path)
			if mode == "edited" {
				raw = bytes.Replace(raw, []byte("participant-action"), []byte("private-canary"), 1)
				os.WriteFile(path, raw, 0600)
			} else {
				os.Remove(path)
				target := filepath.Join(c.Work, "private-file")
				os.WriteFile(target, []byte("private-canary"), 0600)
				os.Symlink(target, path)
			}
			if _, _, err := readAuditActivity(c.Work); err == nil {
				t.Fatal("accepted invalid log")
			}
			if _, err := beginAuditActivity(c); err == nil {
				t.Fatal("admitted operation")
			}
		})
	}
}
func TestAuditActivityCompletionFailureDoesNotReplaceResult(t *testing.T) {
	c := activityTestContext(t)
	finish, err := beginAuditActivity(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Work, diagnosticDirectory, auditActivityFile)
	os.Remove(path)
	os.Mkdir(path, 0700)
	var output bytes.Buffer
	finish(errors.New("private-canary-secret"), &output)
	if !strings.Contains(output.String(), "action result is unchanged") || strings.Contains(output.String(), "private-canary") {
		t.Fatal(output.String())
	}
}
func TestAuditActivitySanitizesErrorsAndAction(t *testing.T) {
	c := activityTestContext(t)
	c.Action = "private-canary"
	c.Role = "private-canary"
	c.Stage = "private-canary"
	if err := appendAuditActivity(c, "failed", errors.New("private-canary"), "private-canary"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(c.Work, diagnosticDirectory, auditActivityFile))
	if bytes.Contains(raw, []byte("private-canary")) {
		t.Fatal("canary leaked")
	}
}

func TestAuditActivityUnavailablePreventsGuideAction(t *testing.T) {
	protocol, b := workflowV4TestBinding(t)
	protocol.Definition.Phase1Participants = []string{b.IdentityID}
	p, saved := guidePhaseProfile(t, b)
	snapshot := guidePhaseSnapshot(t, protocol, b, "phase1")
	j, err := openWorkflowV4Journal(protocol, b.Definition, b)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	root, err := diagnosticRoot(p.Work, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, auditActivityFile), 0700); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(j.state)
	var out bytes.Buffer
	ui := coordinatorWizard{input: bufio.NewReader(strings.NewReader("1\nQ\n")), output: &out}
	err = runWorkflowV4GuideLoop(p, guidedProfile{}, setupIdentity{ID: b.IdentityID}, protocol, j, access.StorageConfig{}, transcript.Inspector{}, "/must-not-run/docker", &saved, &ui, func() (storagefirst.SnapshotV4, error) { return snapshot, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "activity recording unavailable; action was not started") {
		t.Fatal(out.String())
	}
	if strings.Contains(out.String(), "Participant action stopped:") || strings.Contains(out.String(), "Action finished locally.") {
		t.Fatal("action ran despite recording failure", out.String())
	}
	after, _ := json.Marshal(j.state)
	if !bytes.Equal(before, after) {
		t.Fatal("operation state changed")
	}
}

func TestAuditActivityDiagnosticProjectionSharesTimestamp(t *testing.T) {
	c := activityTestContext(t)
	recordDiagnostic(c, "succeeded", nil, nil)
	events, _, err := readAuditActivity(c.Work)
	if err != nil {
		t.Fatal(err)
	}
	root, err := diagnosticRoot(c.Work, false)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := readDiagnosticEvents(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || len(legacy) != 1 {
		t.Fatal("missing projection")
	}
	events[0].Sequence = 0
	if events[0] != legacy[0] {
		t.Fatal("diagnostic projections differ")
	}
}
