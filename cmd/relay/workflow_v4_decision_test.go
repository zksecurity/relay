package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestWorkflowV4DecisionAvailabilityRequiresProductionV5FinalRelease(t *testing.T) {
	p := transcript.DefinitionProtocol{DefinitionSchema: "proof-tool-mpc-ceremony-definition-v5", Definition: transcript.Definition{Mode: "production"}}
	s := transcript.CheckpointStateV4{}
	for _, role := range []string{"coordinator", "auditor", "release-signer"} {
		if workflowV4DecisionAvailable(p, s, role) {
			t.Fatalf("%s offered decision before release", role)
		}
	}
	s.Progress.FinalRelease = &transcript.SignedArtifactRefs{}
	for _, role := range []string{"coordinator", "auditor", "release-signer"} {
		if !workflowV4DecisionAvailable(p, s, role) {
			t.Fatalf("%s missing decision after release", role)
		}
	}
	if workflowV4DecisionAvailable(p, s, "participant") {
		t.Fatal("participant offered decision")
	}
	p.Definition.Mode = "rehearsal"
	if workflowV4DecisionAvailable(p, s, "coordinator") {
		t.Fatal("rehearsal offered decision")
	}
	p.Definition.Mode = "production"
	p.DefinitionSchema = "proof-tool-mpc-ceremony-definition-v4"
	if workflowV4DecisionAvailable(p, s, "coordinator") {
		t.Fatal("V4 expectations silently changed")
	}
	p.DefinitionSchema = "proof-tool-mpc-ceremony-definition-v5"
	s.Progress.Terminal = &struct {
		Kind              string                         `json:"kind"`
		Record            transcript.SignedArtifactRefs  `json:"record"`
		RestartDefinition *transcript.SignedArtifactRefs `json:"restart_definition,omitempty"`
	}{Kind: "abort"}
	if workflowV4DecisionAvailable(p, s, "coordinator") {
		t.Fatal("terminal ceremony offered decision")
	}
}

func TestWorkflowV4DecisionSigningUsesOfflineProfileAndPreservesOutput(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	for _, dir := range []string{filepath.Join(work, "ceremony", "public"), filepath.Join(work, "decision-evidence")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	decision := filepath.Join(work, "decision.json")
	if err := os.WriteFile(decision, []byte(`{"ceremony_id":"ceremony-test","decision":"GO"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := guidedProfile{Role: "release-signer", Work: work, Trust: trust, Keys: keys, ReleaseCommit: strings.Repeat("a", 40)}
	signer := guidedProfile{Role: "decision-signer", Work: work, Trust: trust, Keys: keys, ReleaseCommit: profile.ReleaseCommit, Image: "example.test/offline@sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64"}
	protocol := transcript.DefinitionProtocol{DefinitionSchema: "proof-tool-mpc-ceremony-definition-v5", Definition: transcript.Definition{Mode: "production", CeremonyID: "ceremony-test"}}
	previous := workflowV4ChildExecutor
	defer func() { workflowV4ChildExecutor = previous }()
	var launch []string
	workflowV4ChildExecutor = func(args []string) error { launch = append([]string(nil), args...); return nil }
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("2\nSIGN DECISION\n")), output: &bytes.Buffer{}}
	if err := runWorkflowV4DecisionMenu(ui, profile, signer, setupIdentity{ID: "release-signer-test"}, protocol); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(launch, " ")
	for _, part := range []string{"--role decision-signer", signer.Image, "decision sign", "--evidence-root /work/decision-evidence", "--role release_signer", "--signer-id release-signer-test", "--signing-key /keys/signing.hex"} {
		if !strings.Contains(joined, part) {
			t.Fatalf("offline signing launch lacks %q: %s", part, joined)
		}
	}
	if err := os.WriteFile(filepath.Join(work, "decision-release-signer.sig"), []byte("retained"), 0o600); err != nil {
		t.Fatal(err)
	}
	launch = nil
	ui = &coordinatorWizard{input: bufio.NewReader(strings.NewReader("2\n")), output: &bytes.Buffer{}}
	if err := runWorkflowV4DecisionMenu(ui, profile, signer, setupIdentity{ID: "release-signer-test"}, protocol); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("retained signature was not protected: %v", err)
	}
	if launch != nil {
		t.Fatal("retained signature triggered another signing command")
	}
}

func TestWorkflowV4DecisionRejectsWrongCeremonyBeforeSigning(t *testing.T) {
	work := t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "decision-evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "decision.json"), []byte(`{"ceremony_id":"other","decision":"GO"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("")), output: &bytes.Buffer{}}
	if err := requireDecisionEvidence(filepath.Join(work, "decision.json"), filepath.Join(work, "decision-evidence"), "expected", ui); err == nil {
		t.Fatal("wrong ceremony decision accepted")
	}
}

func TestWorkflowV4DecisionInterruptedSigningNeedsExplicitSameDecisionRetry(t *testing.T) {
	work := t.TempDir()
	decision := filepath.Join(work, "decision.json")
	output := filepath.Join(work, "decision-release-signer.sig")
	if err := os.WriteFile(decision, []byte("first exact decision"), 0o600); err != nil {
		t.Fatal(err)
	}
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("")), output: &bytes.Buffer{}}
	if err := retainDecisionSigningAttempt(ui, work, "release-signer", "signer", decision, output); err != nil {
		t.Fatal(err)
	}
	if err := retainDecisionSigningAttempt(ui, work, "release-signer", "signer", decision, output); err == nil {
		t.Fatal("retry proceeded without review")
	}
	if err := os.WriteFile(decision, []byte("changed decision"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := retainDecisionSigningAttempt(ui, work, "release-signer", "signer", decision, output); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("changed decision retry: %v", err)
	}
	if err := os.WriteFile(decision, []byte("first exact decision"), 0o600); err != nil {
		t.Fatal(err)
	}
	ui = &coordinatorWizard{input: bufio.NewReader(strings.NewReader("RETRY DECISION SIGNING\n")), output: &bytes.Buffer{}}
	if err := retainDecisionSigningAttempt(ui, work, "release-signer", "signer", decision, output); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowV4DecisionVerifyPassesEverySignatureToPinnedTool(t *testing.T) {
	work, trust, keys := t.TempDir(), t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(work, "decision-evidence"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "decision.json"), []byte(`{"ceremony_id":"ceremony-test","decision":"NO-GO"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(work, "coordinator.sig"), filepath.Join(work, "auditor-one.sig"), filepath.Join(work, "auditor-two.sig")}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("signature"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := guidedProfile{Role: "coordinator", Work: work, Trust: trust, Keys: keys, ReleaseCommit: strings.Repeat("a", 40)}
	signer := guidedProfile{Role: "decision-signer", Work: work, Trust: trust, Keys: keys, ReleaseCommit: p.ReleaseCommit, Image: "example.test/offline@sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64"}
	protocol := transcript.DefinitionProtocol{DefinitionSchema: "proof-tool-mpc-ceremony-definition-v5", Definition: transcript.Definition{Mode: "production", CeremonyID: "ceremony-test"}}
	previous := workflowV4ChildExecutor
	defer func() { workflowV4ChildExecutor = previous }()
	var launch []string
	workflowV4ChildExecutor = func(args []string) error { launch = append([]string(nil), args...); return nil }
	ui := &coordinatorWizard{input: bufio.NewReader(strings.NewReader("3\n" + strings.Join(paths, "\n") + "\n\n")), output: &bytes.Buffer{}}
	if err := runWorkflowV4DecisionMenu(ui, p, signer, setupIdentity{ID: "coordinator-test"}, protocol); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(launch, " ")
	if !strings.Contains(joined, "decision verify") || strings.Count(joined, "--signature") != len(paths) {
		t.Fatalf("wrong threshold verification command: %s", joined)
	}
	for _, want := range []string{"/work/coordinator.sig", "/work/auditor-one.sig", "/work/auditor-two.sig"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %s", want, joined)
		}
	}
}
