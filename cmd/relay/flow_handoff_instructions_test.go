package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestPublicImportDefaultMatchesMissingStorage(t *testing.T) {
	for _, role := range []string{"participant", "witness", "mirror", "auditor", "upload-station", "release-signer"} {
		t.Run(role, func(t *testing.T) {
			p, _, inputs := importSetFixture(t, role)
			if p.defaultPublicImport() != "ceremony-set" {
				t.Fatal("missing ceremony set not recommended")
			}
			for n, file := range ceremonyImportFiles {
				if err := publishPublicInput(preparationDestination(p.d, file.kind), inputs[n]); err != nil {
					t.Fatal(err)
				}
			}
			want := "storage"
			if role == "release-signer" {
				want = ""
			}
			if p.defaultPublicImport() != want {
				t.Fatalf("got %q want %q", p.defaultPublicImport(), want)
			}
			p.ui.input = bufio.NewReader(strings.NewReader(""))
			_ = p.importFile()
			out := p.ui.output.(*bytes.Buffer).String()
			if role != "release-signer" && !strings.Contains(out, "Choose a number [4]") {
				t.Fatal(out)
			}
			if strings.Contains(out, "folder (recommended)") {
				t.Fatal("fixed recommendation remains")
			}
			if err := publishPublicInput(preparationDestination(p.d, "storage"), []byte("{}")); err != nil {
				t.Fatal(err)
			}
			if p.defaultPublicImport() != "" {
				t.Fatal("present storage treated as missing")
			}
		})
	}
}

func TestAllAuthoredHandoffsHaveInstructions(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		for _, stage := range roleFlowStages(role) {
			for _, task := range stage.Tasks {
				if !task.Handoff {
					continue
				}
				i, ok := handoffInstructionFor(task.ID)
				if !ok || i.counterpart == "" || len(i.next) < 40 {
					t.Fatalf("missing counterpart/action/reply: %s/%s/%s", role, stage.ID, task.ID)
				}
			}
		}
	}
}

func custodyDisplayFixture(t *testing.T, phase string) (*roleFlow, flowTask) {
	t.Helper()
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	f.turnScope = &flowTurnScope{Phase: phase, Participant: "participant-test", Head: "head-test"}
	task := handoff("deliver-input", "Deliver input", "Public only")
	f.stages = []flowStage{{ID: phase + "-turns", Tasks: []flowTask{task}}}
	packetDir := "/work/custom-packet"
	payload := "/work/custom-public/" + phase + "/genesis.bin"
	for path, raw := range map[string][]byte{payload: []byte("public payload"), packetDir + "/record.sig": []byte("signature fixture")} {
		local := flowHostPath(f.state.Profile, path)
		if err := os.MkdirAll(filepath.Dir(local), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(local, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := setupFileHash(flowHostPath(f.state.Profile, payload))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"recipient_id": "participant-test", "files": []transcript.ArtifactRef{{Name: phase + "/genesis.bin", Digest: transcript.Digest{SHA256: "sha256:" + digest, Size: 14}}}})
	if err := os.WriteFile(flowHostPath(f.state.Profile, packetDir+"/canonical.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	f.state.Attempts = []flowAttempt{
		{ID: "prepare", Task: "prepare-outbound-handoff", Stage: phase + "-turns", Status: "succeeded", TurnScope: f.turnScope, Command: []string{"--out-dir", packetDir, "--transcript-root", "/work/custom-public"}},
		{ID: "sign", Task: "sign-outbound-handoff", Stage: phase + "-turns", Status: "succeeded", TurnScope: f.turnScope, Command: []string{"--record", packetDir + "/canonical.json", "--out", packetDir + "/record.sig"}},
	}
	return f, task
}

func TestCustodyHandoffDisplaysExactScopedPublicFiles(t *testing.T) {
	for _, phase := range []string{"phase1", "phase2"} {
		f, task := custodyDisplayFixture(t, phase)
		fields, err := f.showHandoffInstructions(task)
		if err != nil || len(fields) != 3 {
			t.Fatalf("%v %v", fields, err)
		}
		out := f.ui.output.(*bytes.Buffer).String()
		for _, want := range []string{"participant-test", "custom-packet/canonical.json", "custom-packet/record.sig", "custom-public/" + phase + "/genesis.bin", "Verify that receipt before issuing the grant"} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %s: %s", want, out)
			}
		}
		f.state.Attempts = append(f.state.Attempts, flowAttempt{ID: "new-sign", Task: "sign-outbound-handoff", Stage: phase + "-turns", Status: "failed", TurnScope: f.turnScope})
		if _, _, err := f.custodyDeliveryFields(task); err == nil {
			t.Fatal("fell back to earlier signature")
		}
		f.turnScope = &flowTurnScope{Phase: phase, Participant: "different", Head: "different"}
		if _, _, err := f.custodyDeliveryFields(task); err == nil {
			t.Fatal("used another turn")
		}
	}
}

func TestMissingCustodyAllowsWaitingAndProblemNotCompletion(t *testing.T) {
	for _, answer := range []string{"1\n", "2\n", "3\nMissing packet\n"} {
		f := flowFixture(t)
		task := handoff("deliver-input", "Deliver input", "Public only")
		f.stages[0].Tasks = []flowTask{task}
		f.ui.input = bufio.NewReader(strings.NewReader(answer))
		err := f.execute(task)
		if strings.HasPrefix(answer, "1") {
			if err == nil {
				t.Fatal("missing packet reported complete")
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestCustodyRejectsUnsafeOrChangedPayloads(t *testing.T) {
	for _, name := range []string{"../keys/signing.hex", "/keys/signing.hex", "phase1/../genesis.bin", "phase1/missing.bin", "phase1/genesis.bin"} {
		f, task := custodyDisplayFixture(t, "phase1")
		raw, _ := json.Marshal(map[string]any{"recipient_id": "test", "files": []transcript.ArtifactRef{{Name: name, Digest: transcript.Digest{SHA256: "sha256:wrong", Size: 14}}}})
		if err := os.WriteFile(filepath.Join(f.state.Profile.Work, "custom-packet/canonical.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := f.custodyDeliveryFields(task); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestCustodySnapshotDetectsChangeBeforeCapture(t *testing.T) {
	f, task := custodyDisplayFixture(t, "phase1")
	expected := map[string]string{}
	fields, err := f.showHandoffInstructions(task, expected)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.state.Profile.Work, "custom-public/phase1/genesis.bin"), []byte("changed bytes!"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{}
	for _, field := range fields {
		args = append(args, "--record", field.Default)
	}
	bindings, err := f.captureEvidence(flowTask{Fields: fields}, args)
	if err != nil {
		t.Fatal(err)
	}
	if bindings["/work/custom-public/phase1/genesis.bin"] == expected["/work/custom-public/phase1/genesis.bin"] {
		t.Fatal("mutation not detected by expected snapshot")
	}
}

func TestHandoffPublicPathsFollowSavedCommands(t *testing.T) {
	f := flowFixture(t)
	f.stages = []flowStage{{ID: "finalization", Tasks: []flowTask{{ID: "complete", Fields: []flowField{ff("candidate-dir", "Public candidate", "/work/candidate")}}}}}
	f.state.Attempts = []flowAttempt{{ID: "complete", Task: "complete", Stage: "finalization", Status: "succeeded", Command: []string{"--candidate-dir", "/work/custom-candidate"}}}
	if got := f.savedPublicHandoffPath("/work/candidate/candidate.json"); got != "/work/custom-candidate/candidate.json" {
		t.Fatal(got)
	}
}

func TestRetainedCustodyHandoffDisplay(t *testing.T) {
	path := os.Getenv("RELAY_HANDOFF_TEST_STATE")
	if path == "" {
		t.Skip("opt-in read-only retained custody display")
	}
	f := flowFixture(t)
	if err := setupReadJSON(path, &f.state); err != nil {
		t.Fatal(err)
	}
	f.stages = roleFlowStages(f.state.Role)
	var latest *flowAttempt
	for n := len(f.state.Attempts) - 1; n >= 0; n-- {
		if f.state.Attempts[n].Task == "sign-outbound-handoff" {
			latest = &f.state.Attempts[n]
			break
		}
	}
	if latest == nil {
		t.Fatal("no retained signed outbound handoff")
	}
	for n, stage := range f.stages {
		if stage.ID == latest.Stage {
			f.state.Stage = n
		}
	}
	f.turnScope = latest.TurnScope
	expected := map[string]string{}
	fields, err := f.showHandoffInstructions(handoff("deliver-input", "Deliver input", "Public only"), expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) < 3 || len(expected) != len(fields) {
		t.Fatal("packet/payload snapshot incomplete")
	}
	t.Log("Retained packet, detached signature and named public payload paths resolved without changing the ceremony")
}
