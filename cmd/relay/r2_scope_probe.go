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
		client store.Client
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
	coordinator := coordinatorClient(config, config.InboxBucket)
	public := coordinatorClient(config, config.PublishedBucket)
	for _, p := range []probe{{coordinator, outsideKey}, {public, outsideKey}} {
		if err := p.client.PutNoReplace(p.key, source); err != nil {
			return errors.New("cannot create isolated scope probe; check coordinator bucket permissions")
		}
		created = append(created, p)
	}
	scoped := store.Client{Endpoint: config.Endpoint, Region: config.Region, Bucket: config.InboxBucket, Credentials: &store.Credentials{AccessKeyID: credentials.AccessKeyID, SecretAccessKey: credentials.SecretAccessKey, SessionToken: credentials.SessionToken}}
	if err := scoped.PutNoReplace(allowedKey, source); err != nil {
		return errors.New("temporary inbox grant cannot write its allowed prefix; check the parent credential and endpoint")
	}
	created = append(created, probe{coordinator, allowedKey})
	if err := scoped.Get(allowedKey, filepath.Join(dir, "allowed")); err != nil {
		return errors.New("temporary inbox grant cannot read its allowed probe")
	}
	got, err := os.ReadFile(filepath.Join(dir, "allowed"))
	if err != nil || !bytes.Equal(got, data) {
		return errors.New("temporary grant read returned different probe bytes")
	}
	for n, p := range []probe{{scoped, outsideKey}, {store.Client{Endpoint: scoped.Endpoint, Region: scoped.Region, Bucket: config.PublishedBucket, Credentials: scoped.Credentials}, outsideKey}} {
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
			return errors.New("temporary grant write-denial probe inconclusive")
		}
	}
	expired, _, err := issueR2Locally(config, base+"allowed/", time.Minute, time.Now().UTC().Add(-time.Hour), secret)
	if err != nil {
		return err
	}
	scoped.Credentials = &store.Credentials{AccessKeyID: expired.AccessKeyID, SecretAccessKey: expired.SecretAccessKey, SessionToken: expired.SessionToken}
	err = scoped.Get(allowedKey, filepath.Join(dir, "expired"))
	if err == nil {
		return errors.New("expired temporary grant remained usable; do not issue grants")
	}
	if !isAccessDenied(err) && !strings.Contains(strings.ToLower(err.Error()), "expiredtoken") {
		return errors.New("temporary grant expiration probe inconclusive")
	}
	return nil
}
