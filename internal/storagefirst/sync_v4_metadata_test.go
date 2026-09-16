package storagefirst

import (
	"errors"
	"testing"

	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

func TestSyncV4EnrollmentMetadataIsExactAndRequired(t *testing.T) {
	for _, variant := range []string{"ok", "missing-record", "missing-signature", "bad-signature", "wrong-head", "wrong-ceremony", "subset", "different-ref", "overclaim", "nil-commitments"} {
		t.Run(variant, func(t *testing.T) {
			objects, v, id := syncFixtureV4(t, 1)
			artifact := func(name, body string) transcript.ArtifactRef {
				b := []byte(body)
				objects[store.Key(sum(b))] = b
				return transcript.ArtifactRef{Name: name, Digest: transcript.Digest{SHA256: sum(b), Blake2b256: "blake2b256:" + sum(b)[7:], Size: int64(len(b))}}
			}
			pair := transcript.SignedArtifactRefs{Record: artifact("enrollments/one.json", "public enrollment"), Signature: artifact("enrollments/one.sig", "signature")}
			v.full.Commitments.Enrollments = []transcript.SignedArtifactRefs{pair}
			discovery := v.discoveries[v.full.CheckpointRefs.Record.Digest.SHA256]
			discovery.Discovery.Enrollment = &pair
			v.discoveries[v.full.CheckpointRefs.Record.Digest.SHA256] = discovery
			v.metadata = &transcript.EnrollmentMetadataInspectionV4{Schema: "proof-tool-mpc-enrollment-metadata-v4", Depth: "committed-enrollment-signatures", EnrollmentSignaturesVerified: true, Metadata: transcript.EnrollmentMetadataV4{CeremonyID: id, Checkpoint: v.full.CheckpointRefs, Enrollments: []transcript.CommittedEnrollmentMetadataV4{{Refs: pair}}}}
			switch variant {
			case "missing-record":
				delete(objects, store.Key(pair.Record.Digest.SHA256))
			case "missing-signature":
				delete(objects, store.Key(pair.Signature.Digest.SHA256))
			case "bad-signature":
				v.metadataErr = errors.New("signature rejected")
			case "wrong-head":
				v.metadata.Metadata.Checkpoint.Signature.Digest.SHA256 = sum([]byte("other"))
			case "wrong-ceremony":
				v.metadata.Metadata.CeremonyID = sum([]byte("other"))
			case "subset":
				v.metadata.Metadata.Enrollments = []transcript.CommittedEnrollmentMetadataV4{}
			case "different-ref":
				v.metadata.Metadata.Enrollments[0].Refs.Record.Name = "loose.json"
			case "overclaim":
				v.metadata.CompleteRosterVerified = true
			case "nil-commitments":
				v.full.Commitments.Enrollments = nil
			}
			h := &highWaterFake{}
			snapshot, err := SyncV4(objects, v, h, id, t.TempDir())
			if variant != "ok" {
				if err == nil {
					t.Fatal("incomplete metadata produced guidance snapshot")
				}
				if _, err := snapshot.State(); err == nil {
					t.Fatal("failure exposed state")
				}
				if _, err := snapshot.Enrollments(); err == nil {
					t.Fatal("failure exposed enrollments")
				}
				if h.exists {
					t.Fatal("metadata failure advanced high-water")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.metadataCalls != 1 || v.fullCalls != 1 {
				t.Fatal("enrollments not batched")
			}
			commitments, err := snapshot.Commitments()
			if err != nil {
				t.Fatal(err)
			}
			commitments.Enrollments[0].Record.Name = "changed"
			enrollments, err := snapshot.Enrollments()
			if err != nil {
				t.Fatal(err)
			}
			enrollments.Enrollments[0].Refs.Record.Name = "changed"
			c, _ := snapshot.Commitments()
			e, _ := snapshot.Enrollments()
			if c.Enrollments[0] != pair || e.Enrollments[0].Refs != pair {
				t.Fatal("snapshot facts mutable through caller alias")
			}
		})
	}
}

func TestSyncV4MissingMetadataRetry(t *testing.T) {
	objects, v, id := syncFixtureV4(t, 1)
	h := &highWaterFake{}
	v.metadataErr = errors.New("temporarily unavailable")
	if _, err := SyncV4(objects, v, h, id, t.TempDir()); err == nil || h.exists {
		t.Fatal("incomplete metadata advanced progress")
	}
	v.metadataErr = nil
	if _, err := SyncV4(objects, v, h, id, t.TempDir()); err != nil || !h.exists || h.position.Sequence != 1 {
		t.Fatal("corrected metadata did not resume", err)
	}
}
