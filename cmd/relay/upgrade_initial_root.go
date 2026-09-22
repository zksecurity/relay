package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// Authenticate publication independently of the failed public refresh. This is
// admission only: it creates neither a checkpoint nor a high-water record.
func upgradeInitialPublishedRoot(p guidedProfile, ceremonyID string) (state.Root, func() error, error) {
	var zero state.Root
	config, err := loadStorageConfig(filepath.Join(p.Work, "ceremony/config/relay-storage.json"))
	if err != nil {
		return zero, nil, err
	}
	if config.CeremonyID != ceremonyID || config.Provider != "aws" {
		return zero, nil, errors.New("initial upgrade requires authenticated AWS storage or an existing verified refresh")
	}
	binding, err := readAWSLoginBinding(p.Credentials)
	if err != nil {
		return zero, nil, err
	}
	if binding == nil {
		return zero, nil, errors.New("initial upgrade requires a configured host AWS login binding")
	}
	credentials, err := refreshAWSLogin(context.Background(), *binding)
	if err != nil {
		return zero, nil, err
	}
	client := coordinatorClient(config, config.PublishedBucket)
	client.Profile = ""
	client.Credentials = &store.Credentials{AccessKeyID: credentials.AccessKeyId, SecretAccessKey: credentials.SecretAccessKey, SessionToken: credentials.SessionToken}
	read := func() (state.Root, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		temp, err := os.MkdirTemp("", "relay-upgrade-root-")
		if err != nil {
			return zero, err
		}
		defer os.RemoveAll(temp)
		path := filepath.Join(temp, "root.json")
		if _, err := client.WithContext(ctx).GetVersionedAtMost(state.RootKey(ceremonyID), path, 1<<20); err != nil {
			return zero, err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return zero, err
		}
		root, err := state.DecodeRoot(raw)
		if err != nil {
			return zero, err
		}
		if root.CeremonyID != ceremonyID {
			return zero, errors.New("storage root belongs to another ceremony")
		}
		return root, nil
	}
	root, err := read()
	if err != nil {
		return zero, nil, err
	}
	return root, func() error {
		current, err := read()
		if err != nil {
			return err
		}
		if current != root {
			return errors.New("published root changed during upgrade review; retry from current progress")
		}
		return nil
	}, nil
}

func upgradeMatchInitialRoot(root state.Root, checked transcript.CheckpointInspectionV4) error {
	c := checked.Checkpoint
	refs := checked.CheckpointRefs
	if c.CeremonyID != root.CeremonyID || c.Sequence != 0 || c.PreviousCheckpoint != nil {
		return errors.New("missing-refresh upgrade only supports the published initial checkpoint")
	}
	for _, pair := range []struct {
		remote state.ContentRef
		local  transcript.ArtifactRef
	}{
		{root.Checkpoint, refs.Record}, {root.CheckpointSignature, refs.Signature},
	} {
		if pair.remote.Name != pair.local.Name || pair.remote.SHA256 != pair.local.Digest.SHA256 || pair.remote.Size != pair.local.Digest.Size {
			return errors.New("published root differs from authenticated local initial checkpoint")
		}
	}
	return nil
}
