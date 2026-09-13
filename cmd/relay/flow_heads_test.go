package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestDockerAuthenticatedHeadDiscovery(t *testing.T) {
	if os.Getenv("RELAY_FLOW_DOCKER") != "1" {
		t.Skip("opt-in Docker authenticated discovery")
	}
	work := os.Getenv("RELAY_HEAD_TEST_WORK")
	if work == "" {
		t.Skip("supply a completed local rehearsal work folder")
	}
	root := filepath.Join(work, "ceremony/public")
	stateRoot := privateRoleTestDir(t)
	f := roleFlow{state: roleFlowState{Values: map[string]string{}, Profile: guidedProfile{Work: work, Trust: root, Image: os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), Platform: os.Getenv("RELAY_ROLE_PLATFORM")}}, path: filepath.Join(stateRoot, "head-state.json"), ui: coordinatorWizard{output: new(bytes.Buffer)}}
	definition, err := f.authenticatedDefinition()
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := definition.RequireJourney()
	if err != nil || len(requirements.RequiredEnrollments) != 7 {
		t.Fatalf("expected coordinator, final signer, two auditors and three participants: %+v %v", requirements, err)
	}
	journey, err := f.authenticatedJourney()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range journey.Phases {
		if !p.Closed || p.CloseID == "" || p.WitnessObservationDeadline == "" || p.BeaconScheduledAt == "" {
			t.Fatalf("missing authenticated phase timing: %+v", p)
		}
	}
	for _, phase := range []string{"phase1", "phase2"} {
		head, err := f.discoverHead(phase, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(head.Chain.Records) != 3 {
			t.Fatalf("expected complete three-contribution %s head, got %+v", phase, head.Chain)
		}
		again, err := f.discoverHead(phase, nil)
		if err != nil || again.Digest != head.Digest {
			t.Fatalf("resume: %+v %v", again, err)
		}
	}
}

// Read-only released-pair regression: no transcript mutation or ceremony action.
func TestDockerAuthenticatedDefinitionRequirements(t *testing.T) {
	if os.Getenv("RELAY_DEFINITION_DOCKER") != "1" {
		t.Skip("opt-in released Docker definition inspection")
	}
	work := os.Getenv("RELAY_HEAD_TEST_WORK")
	if work == "" {
		t.Fatal("supply public ceremony work folder")
	}
	root := filepath.Join(work, "ceremony/public")
	f := roleFlow{state: roleFlowState{Values: map[string]string{}, Profile: guidedProfile{Work: work, Trust: root, Image: os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), Platform: os.Getenv("RELAY_ROLE_PLATFORM")}}, path: filepath.Join(privateRoleTestDir(t), "state.json"), ui: coordinatorWizard{output: new(bytes.Buffer)}}
	d, err := f.authenticatedDefinition()
	if err != nil {
		t.Fatal(err)
	}
	j, err := d.RequireJourney()
	if err != nil {
		t.Fatal(err)
	}
	if j.MinimumPublicWitnesses != 1 || j.MinimumMirrorsPerAcceptedHead != 1 {
		t.Fatal("expected current released one-observer requirements", j)
	}
	auditors := 0
	for _, e := range j.RequiredEnrollments {
		if e.Role == "auditor" {
			auditors++
		}
	}
	if auditors != 1 {
		t.Fatal("expected one-auditor regression fixture", auditors)
	}
	t.Log("Authenticated released definition accepted with one auditor, one witness and one mirror")
}

func TestDockerOneObserverEnrollmentCollection(t *testing.T) {
	if os.Getenv("RELAY_DEFINITION_DOCKER") != "1" {
		t.Skip("opt-in released enrollment verification")
	}
	source := os.Getenv("RELAY_ENROLLMENT_TEST_SOURCE")
	if source == "" {
		t.Skip("supply public enrollment fixture")
	}
	work := privateRoleTestDir(t)
	root := filepath.Join(work, "ceremony/public")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ceremony.json", "ceremony.sig", "coordinator-public-key.hex"} {
		raw, err := readPreparationInput(filepath.Join(os.Getenv("RELAY_HEAD_TEST_WORK"), "ceremony/public", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	dest := filepath.Join(root, "collected-enrollments", "received")
	if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		t.Fatal(err)
	}
	if err := importPublicEnrollment(source, dest); err != nil {
		t.Fatal(err)
	}
	f := roleFlow{state: roleFlowState{Values: map[string]string{}, Profile: guidedProfile{Work: work, Trust: root, Image: os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), Platform: os.Getenv("RELAY_ROLE_PLATFORM")}}, path: filepath.Join(work, "state.json"), ui: coordinatorWizard{output: new(bytes.Buffer)}}
	complete, err := f.collectedEnrollments()
	if err != nil {
		t.Fatal(err)
	}
	if complete {
		t.Fatal("one enrollment incorrectly completed the whole collection")
	}
	if !bytes.Contains(f.ui.output.(*bytes.Buffer).Bytes(), []byte("Verified — participant")) {
		t.Fatal(f.ui.output.(*bytes.Buffer).String())
	}
	t.Log("Released participant enrollment verified; absent roles remain missing, not an observer-requirements error")
}

func TestSelectAuthenticatedFlowHead(t *testing.T) {
	head := func(path, digest string, ids ...string) flowHead {
		h := flowHead{Chain: transcript.Chain{CeremonyID: "ceremony", Phase: "phase1", ChainPath: path}, Digest: digest}
		for n, id := range ids {
			h.Chain.Records = append(h.Chain.Records, transcript.ChainRecord{Index: uint8(n + 1), RecordID: id})
		}
		return h
	}
	genesis := head("chain-9999.json", "genesis")
	one := head("chain-0003.json", "one", "a")
	two := head("chain-0001.json", "two", "a", "b")
	best, err := selectFlowHead([]flowHead{two, genesis, one}, flowHeadCheckpoint{})
	if err != nil || best.Digest != "two" {
		t.Fatalf("selected by filename or failed on genesis: %+v %v", best, err)
	}
	if _, err := selectFlowHead([]flowHead{two}, flowHeadCheckpoint{Count: 1, LastID: "a", Digest: "one"}); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		heads    []flowHead
		previous flowHeadCheckpoint
	}{
		"empty":               {},
		"fork":                {heads: []flowHead{two, head("fork", "fork", "x")}},
		"same-position":       {heads: []flowHead{one, head("another", "changed", "a")}},
		"rollback":            {heads: []flowHead{one}, previous: flowHeadCheckpoint{Count: 2, LastID: "b", Digest: "two"}},
		"checkpoint-fork":     {heads: []flowHead{two}, previous: flowHeadCheckpoint{Count: 1, LastID: "x", Digest: "fork"}},
		"negative-checkpoint": {heads: []flowHead{two}, previous: flowHeadCheckpoint{Count: -1}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := selectFlowHead(c.heads, c.previous); err == nil {
				t.Fatal("accepted unsafe head")
			}
		})
	}
}
