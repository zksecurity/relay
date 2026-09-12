package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

// Child-container transport hook for the full Docker rehearsal. No signing key
// is mounted here: credentials issue only a scoped upload grant; acceptance is
// a separate coordinator container action.
func TestAWSLiveCandidateTransport(t *testing.T) {
	if os.Getenv("RELAY_AWS_CANDIDATE_APPROVED") != "1" {
		t.Skip("full AWS ceremony hook only")
	}
	config, err := loadStorageConfig("/work/ceremony/config/relay-storage.json")
	if err != nil {
		t.Fatal(err)
	}
	requireAWSLiveConfiguration(t, config)
	phase, id, candidate := os.Getenv("RELAY_TEST_PHASE"), os.Getenv("RELAY_TEST_ID"), os.Getenv("RELAY_TEST_CANDIDATE")
	if (phase != "phase1" && phase != "phase2") || filepath.Dir(candidate) != "/work/"+phase+"-candidates" {
		t.Fatal("unexpected candidate path")
	}
	o := roleOpts{root: "/work/ceremony/public", definition: config.CeremonyPath, definitionSig: config.CeremonySignature, coordinatorKey: config.CoordinatorPublicKey, ceremonyBinary: config.CeremonyBinary, phase: phase, role: id}
	o.client.PublicBaseURL = config.PublishedBaseURL
	o.client.Bucket = config.PublishedBucket
	if phase == "phase2" {
		o.phase1Seal = "/work/ceremony/public/phase1/sealed/seal.json"
		o.phase1SealSig = "/work/ceremony/public/phase1/sealed/seal.sig"
	}
	pos, err := resolvePosition(o)
	if err != nil {
		t.Fatal(err)
	}
	if pos.nextID != id {
		t.Fatal("candidate out of published turn")
	}
	inspector := transcript.Inspector{Executable: config.CeremonyBinary, CeremonyPath: config.CeremonyPath, CeremonySignaturePath: config.CeremonySignature, CoordinatorPublicKeyPath: config.CoordinatorPublicKey}
	if _, err := inspector.Definition(); err != nil {
		t.Fatal(err)
	}
	prefix, err := access.Prefix(config.CeremonyID, access.RoleParticipant, id)
	if err != nil {
		t.Fatal(err)
	}
	credentials, _, err := issueAWS(config, id, prefix, 15*time.Minute)
	if err != nil {
		t.Fatal("grant issuance failed")
	}
	grant := access.Grant{CeremonyID: config.CeremonyID, IdentityID: id, Prefix: prefix, Credentials: credentials, Region: config.Region, InboxBucket: config.InboxBucket}
	attempt, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := prepareCandidateManifest(candidate, grant, phase, pos, attempt, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(candidate, "aws-test-manifest.json")
	if err := writeJSONNoReplace(manifestPath, manifest, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := uploadCandidate(grantClient(grant), prefix, candidate, manifestPath, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(candidate, "aws-manifest-key.txt"), []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("candidate uploaded through scoped STS session; coordinator acceptance remains separate")
}
