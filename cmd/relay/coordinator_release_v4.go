package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
)

// runCoordinatorFetchReleaseV4 downloads a dynamically sized signed release
// package through coordinator-authenticated inbox access. The trusted storage
// manifest frames transport only; proof-tool must authenticate the package.
func runCoordinatorFetchReleaseV4(args []string) error {
	set := flag.NewFlagSet("coordinator fetch-release-v4", flag.ContinueOnError)
	var storagePath, attempt, out string
	set.StringVar(&storagePath, "storage", "", "verified storage configuration")
	set.StringVar(&attempt, "attempt-id", "", "exact release transport attempt")
	set.StringVar(&out, "out-dir", "", "fresh private release download directory")
	if err := set.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{"--storage": storagePath, "--out-dir": out} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s requires an absolute clean path", name)
		}
	}
	if attempt == "" {
		return errors.New("--attempt-id is required")
	}
	if _, err := os.Lstat(out); err == nil {
		return errors.New("release download directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ensurePrivateDirectory(filepath.Dir(out)); err != nil {
		return err
	}
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	scope := storagefirst.DeliveryScope{CeremonyID: config.CeremonyID, AttemptID: attempt, Kind: access.SubmissionKindRelease}
	temporary, _, err := storagefirst.FetchReleaseDelivery(coordinatorClient(config, config.InboxBucket), scope, filepath.Dir(out))
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, out); err != nil {
		_ = os.RemoveAll(temporary)
		return err
	}
	if err := syncDirectory(filepath.Dir(out)); err != nil {
		return err
	}
	fmt.Printf("Downloaded and transport-checked the signed release package to %s. It is not accepted; proof-tool must authenticate it.\n", out)
	return nil
}
