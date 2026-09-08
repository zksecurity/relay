package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFlowEvidenceChangedInputBlocksAdvancement(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	file := filepath.Join(f.state.Profile.Work, "record.json")
	if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	task := flowTask{ID: "verify", Fields: []flowField{ff("record", "Public record", "/work/record.json")}}
	f.stages[0].Tasks = []flowTask{task}
	bindings, err := f.captureEvidence(task, []string{"--record", "/work/record.json"})
	if err != nil {
		t.Fatal(err)
	}
	f.state.Attempts = []flowAttempt{{Task: "verify", Stage: "test", Status: "succeeded", InputBindings: bindings}}
	if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.advance(); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatal("stale evidence advanced", err)
	}
}

func TestFlowEvidenceNeverReadsPrivateKeysOrNewOutputs(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	task := flowTask{Fields: []flowField{ff("signing-key", "Private key", "/keys/signing.hex"), ff("grant", "Private grant", "/work/grant.json"), ff("out-dir", "Fresh output", "/work/fresh"), ff("out", "Fresh output file", "/work/fresh.json")}}
	bindings, err := f.captureEvidence(task, []string{"--signing-key", "/keys/signing.hex", "--grant", "/work/grant.json", "--out-dir", "/work/fresh", "--out", "/work/fresh.json"})
	if err != nil || len(bindings) != 0 {
		t.Fatal("private or output input read", err)
	}
}

func TestFlowExternalReportDoesNotReplaceVerification(t *testing.T) {
	f := flowFixture(t)
	f.state.Attempts = []flowAttempt{{Task: "verify", Stage: "test", Status: "reported"}}
	f.ui.input = bufio.NewReader(strings.NewReader("CONTINUE\n"))
	if err := f.advance(); err == nil {
		t.Fatal("external assertion substituted for required command")
	}
}

func TestFlowEvidenceMissingInputStopsBeforeConfirmation(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	task := flowTask{ID: "verify", Fields: []flowField{ff("record", "Public record", "/work/missing.json")}}
	if _, err := f.captureEvidence(task, []string{"--record", "/work/missing.json"}); err == nil {
		t.Fatal("missing input accepted")
	}
}
