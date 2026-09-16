package storagefirst

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

func outboundFixtureV4(t *testing.T, phase string) (SnapshotV4, transcript.DefinitionProtocol, memoryObjects, string) {
	_, p, c, index, e := turnFixtureV4(t, phase)
	objects := memoryObjects{}
	ref := func(name string) transcript.ArtifactRef {
		raw := []byte("public bytes for " + name)
		sha := sum(raw)
		objects[store.Key(sha)] = raw
		return transcript.ArtifactRef{Name: name, Digest: transcript.Digest{SHA256: sha, Blake2b256: "blake2b256:" + strings.Repeat("a", 64), Size: int64(len(raw))}}
	}
	pair := func(name string) transcript.SignedArtifactRefs {
		return transcript.SignedArtifactRefs{Record: ref(name + ".json"), Signature: ref(name + ".sig")}
	}
	c.Definition = pair("ceremony")
	p.DefinitionRefs = c.Definition
	progress := &c.Progress.Phase1
	if phase == "phase2" {
		progress = c.Progress.Phase2
	}
	progress.Chain = pair(phase + "/chain-0000")
	progress.HeadPayload = ref(phase + "/genesis.bin")
	schedule, _ := p.Definition.Schedule(phase)
	who := schedule[0]
	view, err := encodeTurnFixtureV4(t, c, index, e).TurnV4(p, phase, who)
	if err != nil {
		t.Fatal(err)
	}
	attempt := strings.Repeat("ab", 16)
	index.Turns = []transcript.TurnCommitmentV4{{Scope: view.Scope, Outbounds: []transcript.OutboundCommitmentV4{{Pair: pair("custody/outbound"), PublishedAttemptID: attempt, CheckpointSequence: 1}}}}
	c.Deliveries = []transcript.DeliverySlotV4{{Scope: view.Scope, Kind: "receipt", AttemptID: attempt, Status: "allocated"}}
	return encodeTurnFixtureV4(t, c, index, e), p, objects, who
}

func TestFetchOutboundV4PlacesReceiptInputsBothPhases(t *testing.T) {
	for _, phase := range []string{"phase1", "phase2"} {
		s, p, objects, who := outboundFixtureV4(t, phase)
		parent := t.TempDir()
		result, err := s.FetchOutboundV4(objects, p, phase, who, parent)
		if err != nil {
			t.Fatal(err)
		}
		if result.Scope.ParticipantID != who || len(result.Files) != 7 {
			t.Fatal("wrong receipt input set")
		}
		for _, ref := range result.Files {
			raw, err := os.ReadFile(filepath.Join(result.Root, ref.Name))
			if err != nil || sum(raw) != ref.Digest.SHA256 {
				t.Fatal("missing or changed input", ref.Name, err)
			}
		}
		if _, err := os.Stat(filepath.Join(result.Root, phase, "genesis.bin")); err != nil {
			t.Fatal("payload logical path missing", err)
		}
		second, err := s.FetchOutboundV4(objects, p, phase, who, parent)
		if err != nil || second.Root == result.Root {
			t.Fatal("repeat overwrote earlier download", err)
		}
	}
}

func TestFetchOutboundV4FailureRetainsNoReturnedDirectory(t *testing.T) {
	s, p, objects, who := outboundFixtureV4(t, "phase1")
	for _, broken := range []string{"missing", "corrupt"} {
		t.Run(broken, func(t *testing.T) {
			copy := memoryObjects{}
			for key, raw := range objects {
				copy[key] = raw
			}
			c, _ := s.State()
			key := store.Key(c.Progress.Phase1.HeadPayload.Digest.SHA256)
			if broken == "missing" {
				delete(copy, key)
			} else {
				copy[key] = []byte(strings.Repeat("x", len(copy[key])))
			}
			parent := t.TempDir()
			result, err := s.FetchOutboundV4(copy, p, "phase1", who, parent)
			if err == nil || result.Root != "" {
				t.Fatal("failed download returned usable inputs")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatal("failed staging retained", err)
			}
		})
	}
	if _, err := s.FetchOutboundV4(objects, p, "phase1", "p2", t.TempDir()); err == nil {
		t.Fatal("later participant downloaded another turn")
	}
	c, _ := s.State()
	index, _ := s.Commitments()
	e, _ := s.Enrollments()
	c.Deliveries[0].Status = "retired"
	if _, err := encodeTurnFixtureV4(t, c, index, e).FetchOutboundV4(objects, p, "phase1", who, t.TempDir()); err == nil {
		t.Fatal("retired delivery offered")
	}
}

func TestFetchOutboundV4RejectsUnsafeInventoryBeforeStaging(t *testing.T) {
	s, p, objects, who := outboundFixtureV4(t, "phase1")
	for _, mutate := range []func(*transcript.CheckpointStateV4, *transcript.CheckpointCommitmentsV4){
		func(c *transcript.CheckpointStateV4, _ *transcript.CheckpointCommitmentsV4) {
			c.Progress.Phase1.HeadPayload.Name = "../outside"
		},
		func(c *transcript.CheckpointStateV4, _ *transcript.CheckpointCommitmentsV4) {
			c.Progress.Phase1.HeadPayload.Digest.Size = (16 << 30) + 1
		},
		func(c *transcript.CheckpointStateV4, _ *transcript.CheckpointCommitmentsV4) {
			c.Progress.Phase1.Chain.Signature.Digest.Size = 4097
		},
		func(c *transcript.CheckpointStateV4, i *transcript.CheckpointCommitmentsV4) {
			i.Turns[0].Outbounds[0].Pair.Record.Name = c.Progress.Phase1.Chain.Record.Name
		},
		func(c *transcript.CheckpointStateV4, _ *transcript.CheckpointCommitmentsV4) {
			c.Definition.Record.Digest.SHA256 = sum([]byte("other ceremony"))
		},
	} {
		c, _ := s.State()
		index, _ := s.Commitments()
		e, _ := s.Enrollments()
		mutate(&c, &index)
		parent := t.TempDir()
		if _, err := encodeTurnFixtureV4(t, c, index, e).FetchOutboundV4(objects, p, "phase1", who, parent); err == nil {
			t.Fatal("unsafe input set accepted")
		}
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Fatal("invalid metadata created staging", err)
		}
	}
}
