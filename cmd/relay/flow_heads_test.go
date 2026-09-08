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
