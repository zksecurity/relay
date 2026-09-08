package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/store"
)

type scopeProbeStore struct {
	Bucket       string
	PutNoReplace func(string, string) error
	Get          func(string, string) error
	Delete       func(string) error
}

func newScopeProbeStore(c store.Client) scopeProbeStore {
	return scopeProbeStore{c.Bucket, c.PutNoReplace, c.Get, c.Delete}
}

// Only fresh random probe keys are touched, including denial tests. No listing
// or reading another ceremony's namespace is needed to establish restrictions.
func preflightR2GrantScope(config access.StorageConfig) (result error) {
	secret, err := consumeR2Credential(r2ParentSecretEnvironment)
	if err != nil {
		return err
	}
	if secret == "" {
		return errors.New("R2 inbox parent credential is required for temporary grant scope checks")
	}
	return checkR2GrantScope(config, secret, newScopeProbeStore)
}

func checkR2GrantScope(config access.StorageConfig, secret string, clientFor func(store.Client) scopeProbeStore) (result error) {
	id, err := randomID()
	if err != nil {
		return err
	}
	base := "setup-probes/" + id + "/"
	allowedKey, outsideKey := base+"allowed/probe", base+"outside/probe"
	credentials, _, err := issueR2Locally(config, base+"allowed/", 5*time.Minute, time.Now().UTC(), secret)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "relay-scope-probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	data := []byte("relay scoped grant probe " + id + "\n")
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, data, 0600); err != nil {
		return err
	}
	type probe struct {
		client scopeProbeStore
		key    string
	}
	var created []probe
	defer func() {
		for _, p := range created {
			if err := p.client.Delete(p.key); err != nil {
				result = errors.Join(result, fmt.Errorf("scope probe cleanup failed in bucket %s at %s", p.client.Bucket, p.key))
			}
		}
	}()
	coordinator := clientFor(coordinatorClient(config, config.InboxBucket))
	public := clientFor(coordinatorClient(config, config.PublishedBucket))
	for _, p := range []probe{{coordinator, outsideKey}, {public, outsideKey}} {
		if err := p.client.PutNoReplace(p.key, source); err != nil {
			return probeWriteFailure(p.client.Bucket, p.key, err)
		}
		created = append(created, p)
	}
	// A second, differently named credential can still be overprivileged.
	// Verify that the parent itself cannot access the selected public bucket.
	parentPublic := clientFor(store.Client{Endpoint: config.Endpoint, Region: config.Region, Bucket: config.PublishedBucket, Credentials: &store.Credentials{AccessKeyID: config.ParentAccessKeyID, SecretAccessKey: secret}})
	if err := parentPublic.Get(outsideKey, filepath.Join(dir, "parent-denied")); err == nil {
		return errors.New("inbox parent credential can read the public bucket; replace it with an inbox-only credential")
	} else if !isAccessDenied(err) {
		return errors.New("inbox parent public-bucket denial check was inconclusive")
	}
	parentWriteKey := base + "parent-denied-write"
	if err := parentPublic.PutNoReplace(parentWriteKey, source); err == nil {
		created = append(created, probe{public, parentWriteKey})
		return errors.New("inbox parent credential can write the public bucket; replace it with an inbox-only credential")
	} else if !isAccessDenied(err) {
		return probeWriteFailure(public.Bucket, parentWriteKey, err)
	}
	scopedConfig := store.Client{Endpoint: config.Endpoint, Region: config.Region, Bucket: config.InboxBucket, Credentials: &store.Credentials{AccessKeyID: credentials.AccessKeyID, SecretAccessKey: credentials.SecretAccessKey, SessionToken: credentials.SessionToken}}
	scoped := clientFor(scopedConfig)
	if err := scoped.PutNoReplace(allowedKey, source); err != nil {
		return probeWriteFailure(scoped.Bucket, allowedKey, err)
	}
	created = append(created, probe{coordinator, allowedKey})
	if err := scoped.Get(allowedKey, filepath.Join(dir, "allowed")); err != nil {
		return errors.New("temporary inbox grant cannot read its allowed probe")
	}
	got, err := os.ReadFile(filepath.Join(dir, "allowed"))
	if err != nil || !bytes.Equal(got, data) {
		return errors.New("temporary grant read returned different probe bytes")
	}
	for n, p := range []probe{{scoped, outsideKey}, {clientFor(store.Client{Endpoint: scopedConfig.Endpoint, Region: scopedConfig.Region, Bucket: config.PublishedBucket, Credentials: scopedConfig.Credentials}), outsideKey}} {
		err := p.client.Get(p.key, filepath.Join(dir, fmt.Sprintf("denied-%d", n)))
		if err == nil {
			return errors.New("temporary grant read outside its allowed inbox prefix; do not issue grants")
		}
		if !isAccessDenied(err) {
			return errors.New("temporary grant denial probe inconclusive; resolve connectivity or provider errors before proceeding")
		}
		key := base + fmt.Sprintf("outside/write-%d", n)
		err = p.client.PutNoReplace(key, source)
		if err == nil {
			owner := coordinator
			if n == 1 {
				owner = public
			}
			created = append(created, probe{owner, key})
			return errors.New("temporary grant wrote outside its allowed inbox prefix; do not issue grants")
		}
		if !isAccessDenied(err) {
			return probeWriteFailure(p.client.Bucket, key, err)
		}
	}
	expired, _, err := issueR2Locally(config, base+"allowed/", time.Minute, time.Now().UTC().Add(-time.Hour), secret)
	if err != nil {
		return err
	}
	scopedConfig.Credentials = &store.Credentials{AccessKeyID: expired.AccessKeyID, SecretAccessKey: expired.SecretAccessKey, SessionToken: expired.SessionToken}
	scoped = clientFor(scopedConfig)
	err = scoped.Get(allowedKey, filepath.Join(dir, "expired"))
	if err == nil {
		return errors.New("expired temporary grant remained usable; do not issue grants")
	}
	if !isAccessDenied(err) && !strings.Contains(strings.ToLower(err.Error()), "expiredtoken") {
		return errors.New("temporary grant expiration probe inconclusive")
	}
	return nil
}

func probeWriteFailure(bucket, key string, err error) error {
	if errors.Is(err, store.ErrExists) {
		return fmt.Errorf("probe key already exists in bucket %s at %s; it was not replaced or deleted", bucket, key)
	}
	return fmt.Errorf("probe write did not complete reliably in bucket %s at %s; inspect this exact key before retrying because a lost response can leave an object behind", bucket, key)
}
