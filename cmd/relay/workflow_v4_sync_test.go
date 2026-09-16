package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

type forbiddenSyncStoreV4 struct{ t *testing.T }

func (s forbiddenSyncStoreV4) GetVersionedAtMost(string, string, int64) (store.ObjectVersion, error) {
	s.t.Error("storage contacted before validating local trust")
	return store.ObjectVersion{}, errors.New("unexpected storage request")
}

func TestWorkflowV4SyncRejectsWrongLocalTrustBeforeExecution(t *testing.T) {
	protocol, b := workflowV4TestBinding(t)
	p := workflowV4TestPlan(t, b)
	j, err := openWorkflowV4Journal(protocol, b.Definition, b)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	i := transcript.Inspector{CeremonyPath: p.Inputs[2].Path, CeremonySignaturePath: p.Inputs[3].Path, CoordinatorPublicKeyPath: p.Inputs[4].Path}
	wrong := i
	wrong.CeremonyPath = p.Inputs[5].Path
	if _, err := j.syncV4(forbiddenSyncStoreV4{t}, wrong, "/nonexistent/docker"); err == nil {
		t.Fatal("accepted another definition")
	}
	wrong = i
	wrong.CoordinatorPublicKeyPath = filepath.Join(b.Work, "downloaded-key.hex")
	if _, err := j.syncV4(forbiddenSyncStoreV4{t}, wrong, "/nonexistent/docker"); err == nil {
		t.Fatal("accepted key outside trust folder")
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.syncV4(forbiddenSyncStoreV4{t}, i, "/nonexistent/docker"); err == nil {
		t.Fatal("synced without workspace lock")
	}
}
