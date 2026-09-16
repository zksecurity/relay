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

// runCoordinatorFetchEnrollmentV4 downloads one exact immutable enrollment
// transport attempt. It does not authenticate or accept the enrollment; the
// network-disabled proof-tool record-v4 step does that before publication.
func runCoordinatorFetchEnrollmentV4(args []string) error {
	set := flag.NewFlagSet("coordinator fetch-enrollment-v4", flag.ContinueOnError)
	var storagePath, attempt, out string
	set.StringVar(&storagePath, "storage", "", "verified storage configuration")
	set.StringVar(&attempt, "attempt-id", "", "exact enrollment transport attempt")
	set.StringVar(&out, "out-dir", "", "fresh private download directory")
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
		return errors.New("enrollment download directory already exists")
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
	scope := storagefirst.DeliveryScope{CeremonyID: config.CeremonyID, AttemptID: attempt, Kind: access.SubmissionKindEnrollment}
	inventory := storagefirst.DeliveryInventory{"enrollment.json": 16 << 20, "enrollment.sig": 4096, "disclosure.txt": 1 << 20}
	temporary, err := storagefirst.FetchDelivery(coordinatorClient(config, config.InboxBucket), scope, inventory, filepath.Dir(out))
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
	fmt.Printf("Downloaded the exact immutable enrollment attempt to %s. It is not accepted until proof-tool verification and a signed checkpoint succeed.\n", out)
	return nil
}
