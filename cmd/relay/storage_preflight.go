package main

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

type infrastructureReceipt struct {
	Schema         string   `json:"schema"`
	SettingsSHA256 string   `json:"settings_sha256"`
	CheckedAt      string   `json:"checked_at"`
	Checks         []string `json:"checks"`
}

func (s coordinatorStorageSettings) infrastructure() (access.StorageConfig, error) {
	if err := s.validate(); err != nil {
		return access.StorageConfig{}, err
	}
	v := s.Settings
	c := access.StorageConfig{Provider: v["provider"], AccountID: v["account-id"], ParentAccessKeyID: v["parent-access-key-id"], Endpoint: v["endpoint"], Region: v["region"], PublishedBucket: v["published-bucket"], PublishedBaseURL: v["published-base-url"], InboxBucket: v["inbox-bucket"], CoordinatorProfile: v["profile"], IssuerProfile: v["issuer-profile"], GrantRoleARN: v["grant-role-arn"], GrantRoleMaxTTL: v["grant-role-max-ttl"]}
	return c, c.ValidateInfrastructure()
}

func runCheckStorage(args []string) error {
	flags := flag.NewFlagSet("coordinator check-storage", flag.ContinueOnError)
	var settingsPath, out string
	flags.StringVar(&settingsPath, "settings", "", "non-secret infrastructure settings JSON")
	flags.StringVar(&out, "out", "", "fresh local infrastructure check receipt")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if settingsPath == "" || out == "" || len(flags.Args()) != 0 {
		return errors.New("--settings and --out are required")
	}
	var s coordinatorStorageSettings
	if err := setupReadJSON(settingsPath, &s); err != nil {
		return err
	}
	c, err := s.infrastructure()
	if err != nil {
		return err
	}
	digest, err := setupFileHash(settingsPath)
	if err != nil {
		return err
	}
	if err := preflightStorage(c); err != nil {
		return err
	}
	if c.Provider == "r2" {
		if err := preflightR2GrantScope(c); err != nil {
			return err
		}
	}
	after, err := setupFileHash(settingsPath)
	if err != nil || digest != after {
		return errors.New("infrastructure settings changed during checks")
	}
	checks := []string{"published object write and authenticated read", "anonymous published read with exact bytes", "inbox object write", "probe deletion"}
	if c.Provider == "r2" {
		checks = append(checks, "R2 inbox has no enabled managed or custom public domain")
		checks = append(checks, "inbox parent read/write denied on the selected public bucket; other account buckets were not tested")
		checks = append(checks, "temporary grant allowed-prefix read/write, outside-prefix and other-bucket read/write denied, expired grant denied")
	} else {
		checks = append(checks, "anonymous inbox read denied")
	}
	r := infrastructureReceipt{"relay-infrastructure-check-v1", digest, time.Now().UTC().Format(time.RFC3339Nano), checks}
	if err := writeJSONNoReplace(out, r, 0600); err != nil {
		return err
	}
	fmt.Println("Infrastructure checks passed at", r.CheckedAt)
	fmt.Println("No ceremony was initialized or authenticated. These are point-in-time infrastructure checks, not ceremony-specific authorization.")
	return nil
}

func (w *coordinatorWizard) checkStorage() error {
	if w.localAction != nil {
		return errors.New("cloud checks are disabled in the local harness")
	}
	s := coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", w.d.Storage}
	if _, err := s.infrastructure(); err != nil {
		return fmt.Errorf("set up storage first: %w", err)
	}
	if err := validateRoleMount(w.d.Credentials, true); err != nil {
		return errors.New("choose a protected coordinator credentials file in storage settings first")
	}
	if s.Settings["provider"] == "r2" && w.d.R2Control == "" {
		return errors.New("add the R2 privacy-check credential in storage settings first")
	}
	if s.Settings["provider"] == "r2" && w.d.R2Parent == "" {
		return errors.New("add the inbox-only parent credential in storage settings first")
	}
	fmt.Fprintf(w.output, "Check existing storage:\n  Public: %s\n  Published bucket: %s\n  Private inbox: %s\n", s.Settings["published-base-url"], s.Settings["published-bucket"], s.Settings["inbox-bucket"])
	if err := w.confirm("Write randomly named test objects under setup-probes/ and remove only those objects. Provider request charges may apply. No buckets or policies will be created or changed", "CHECK STORAGE"); err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	settings := filepath.Join(filepath.Dir(w.draftPath), "infrastructure-"+id+".json")
	if err := setupWriteNew(settings, s); err != nil {
		return err
	}
	return w.action("infrastructure", "coordinator", []string{"relay", "coordinator", "check-storage", "--settings", "/work/coordinator-setup/" + filepath.Base(settings), "--out", "/work/coordinator-setup/infrastructure-" + id + ".checked.json"}, true)
}

func (w *coordinatorWizard) prepareStorageBeforeInitialization() error {
	if w.localAction != nil {
		return nil
	}
	fmt.Fprintln(w.output, "Storage checks before initialization are Relay's operating procedure, not a cryptographic requirement. Offline preparation is allowed, but does not make the ceremony ready for grants or publication.")
	choice, err := w.choose("Prepare storage before signing the definition", "", []setupChoice{{"check", "Check configured storage, then review initialization"}, {"setup", "Set up storage first"}, {"offline", "Prepare offline without storage"}, {"cancel", "Return to preparation"}})
	if err != nil {
		return err
	}
	switch choice {
	case "setup":
		if err := w.storage(); err != nil {
			return err
		}
		return errors.New("settings saved; check storage before initializing")
	case "check":
		if err := w.checkStorage(); err != nil {
			return err
		}
		w.d.OfflinePreparation = false
		return w.save()
	case "offline":
		if err := w.confirm("Initialize without storage readiness; publication and grants still require verified storage later", "PREPARE OFFLINE"); err != nil {
			return err
		}
		w.d.OfflinePreparation = true
		return w.save()
	default:
		return errors.New("initialization not requested")
	}
}
