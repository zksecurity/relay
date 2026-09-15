package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

type storageFirstSyncFunc func(storagefirst.ObjectStore, storagefirst.Verifier, storagefirst.HighWater, string, string) (storagefirst.Snapshot, error)
type storageFirstDefinitionFunc func(transcript.Inspector) (transcript.Definition, error)

type storageFirstSyncOptions struct {
	ceremony       string
	ceremonySig    string
	coordinatorKey string
	ceremonyID     string
	endpoint       string
	bucket         string
	profile        string
	region         string
	publicURL      string
	workspace      string
	proofTool      string
	role           string
	identity       string
}

func runStorageFirstSync(args []string) error {
	return runStorageFirstSyncWith(args, os.Stdout, storagefirst.Sync, func(inspector transcript.Inspector) (transcript.Definition, error) {
		return inspector.Definition()
	})
}

func runStorageFirstSyncWith(args []string, output io.Writer, syncFn storageFirstSyncFunc, definitionFn storageFirstDefinitionFunc) error {
	set := flag.NewFlagSet("advanced storage-first-sync", flag.ContinueOnError)
	var options storageFirstSyncOptions
	set.StringVar(&options.ceremony, "ceremony", "", "signed ceremony definition")
	set.StringVar(&options.ceremonySig, "ceremony-signature", "", "detached ceremony-definition signature")
	set.StringVar(&options.coordinatorKey, "coordinator-key", "", "independently authenticated coordinator public key")
	set.StringVar(&options.ceremonyID, "ceremony-id", "", "expected tagged ceremony SHA-256 ID")
	set.StringVar(&options.endpoint, "endpoint", "", "authenticated S3-compatible endpoint")
	set.StringVar(&options.bucket, "bucket", "", "published ceremony bucket")
	set.StringVar(&options.profile, "profile", "", "protected AWS CLI profile for published storage")
	set.StringVar(&options.region, "region", "", "optional storage region")
	set.StringVar(&options.publicURL, "public-url", "", "public HTTPS origin serving ceremony objects")
	set.StringVar(&options.workspace, "workspace", "", "this role's persistent workspace")
	set.StringVar(&options.proofTool, "proof-tool", "", "approved mpc-ceremony executable")
	set.StringVar(&options.role, "role", "", "coordinator or participant")
	set.StringVar(&options.identity, "identity", "", "participant identity ID; required for participant role")
	if err := set.Parse(args); err != nil {
		return err
	}
	if len(set.Args()) != 0 {
		return errors.New("unexpected advanced storage-first-sync arguments")
	}
	if syncFn == nil || definitionFn == nil || output == nil {
		return errors.New("storage-first synchronizer, definition verifier, and output are required")
	}
	if err := options.validate(); err != nil {
		return err
	}

	inspector := transcript.Inspector{
		Executable:               options.proofTool,
		CeremonyPath:             options.ceremony,
		CeremonySignaturePath:    options.ceremonySig,
		CoordinatorPublicKeyPath: options.coordinatorKey,
	}
	definition, err := definitionFn(inspector)
	if err != nil {
		return fmt.Errorf("authenticate ceremony definition: %w", err)
	}
	if definition.CeremonyID != options.ceremonyID {
		return errors.New("--ceremony-id does not match the proof-tool-authenticated ceremony definition")
	}
	highWater, err := state.OpenWorkspaceHighWater(options.workspace, options.ceremonyID)
	if err != nil {
		return fmt.Errorf("open workspace checkpoint high-water: %w", err)
	}
	objects := store.Client{
		Profile: options.profile, Endpoint: options.endpoint, Region: options.region,
		Bucket: options.bucket, PublicBaseURL: options.publicURL,
	}
	verifier := storagefirst.ProofToolVerifier{Inspector: inspector}
	snapshot, err := syncFn(objects, verifier, highWater, options.ceremonyID, options.workspace)
	if err != nil {
		return fmt.Errorf("authenticate storage-first ceremony state: %w", err)
	}
	printStorageFirstSnapshot(output, snapshot, options.role, options.identity)
	return nil
}

func (o storageFirstSyncOptions) validate() error {
	paths := []struct{ label, value string }{
		{"--ceremony", o.ceremony}, {"--ceremony-signature", o.ceremonySig},
		{"--coordinator-key", o.coordinatorKey}, {"--workspace", o.workspace},
		{"--proof-tool", o.proofTool},
	}
	for _, item := range paths {
		label, value := item.label, item.value
		if value == "" {
			return fmt.Errorf("%s is required", label)
		}
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute clean path", label)
		}
	}
	files := []struct{ label, path string }{
		{"--ceremony", o.ceremony}, {"--ceremony-signature", o.ceremonySig},
		{"--coordinator-key", o.coordinatorKey}, {"--proof-tool", o.proofTool},
	}
	for _, item := range files {
		label, path := item.label, item.path
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be a regular non-symlink file", label)
		}
	}
	if !canonicalStorageFirstDigest(o.ceremonyID) {
		return errors.New("--ceremony-id must be a canonical tagged SHA-256 digest")
	}
	if o.role != string(storagefirst.Coordinator) && o.role != string(storagefirst.Participant) {
		return errors.New("--role must be coordinator or participant")
	}
	if o.role == string(storagefirst.Participant) {
		if o.identity == "" || len(o.identity) > 512 || strings.ContainsAny(o.identity, "\x00\r\n") {
			return errors.New("--identity is required and must be a safe participant identity ID")
		}
	} else if o.identity != "" {
		return errors.New("--identity applies only to participant role")
	}

	usingPublic := o.publicURL != ""
	usingAuthenticated := o.endpoint != "" || o.bucket != "" || o.profile != "" || o.region != ""
	if usingPublic == usingAuthenticated {
		return errors.New("choose exactly one storage source: --public-url, or --endpoint with --bucket and --profile")
	}
	if usingPublic {
		if err := validateStorageFirstOrigin("--public-url", o.publicURL); err != nil {
			return err
		}
	} else {
		if o.endpoint == "" || o.bucket == "" || o.profile == "" {
			return errors.New("authenticated storage requires --endpoint, --bucket, and --profile")
		}
		if err := validateStorageFirstOrigin("--endpoint", o.endpoint); err != nil {
			return err
		}
		if len(o.bucket) > 255 || strings.ContainsAny(o.bucket, "\x00\r\n") {
			return errors.New("--bucket is invalid")
		}
		if len(o.profile) > 255 || strings.ContainsAny(o.profile, "\x00\r\n") {
			return errors.New("--profile is invalid")
		}
	}
	return nil
}

func validateStorageFirstOrigin(label, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be an HTTPS origin without credentials, query, or fragment", label)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("%s must not contain a path", label)
	}
	return nil
}

func canonicalStorageFirstDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, c := range strings.TrimPrefix(value, "sha256:") {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func printStorageFirstSnapshot(output io.Writer, snapshot storagefirst.Snapshot, role, identity string) {
	stage := snapshot.Checkpoint.Transition
	if snapshot.Checkpoint.Position.Sequence == 0 && stage == "" {
		stage = "initial"
	}
	head := snapshot.Checkpoint.Position.PhaseHeads["phase1"]
	fmt.Fprintln(output, "authenticated storage-first ceremony state")
	fmt.Fprintf(output, "sequence: %d\n", snapshot.Checkpoint.Position.Sequence)
	fmt.Fprintf(output, "stage: %s\n", stage)
	fmt.Fprintf(output, "phase1 accepted: %d\n", snapshot.Checkpoint.Phase1Accepted)
	fmt.Fprintf(output, "phase1 head: %s\n", head.Digest)

	slots := append([]storagefirst.Slot(nil), snapshot.Checkpoint.Slots...)
	sort.Slice(slots, func(i, j int) bool {
		if slots[i].Phase != slots[j].Phase {
			return slots[i].Phase < slots[j].Phase
		}
		if slots[i].Index != slots[j].Index {
			return slots[i].Index < slots[j].Index
		}
		if slots[i].Kind != slots[j].Kind {
			return slots[i].Kind < slots[j].Kind
		}
		return slots[i].AttemptID < slots[j].AttemptID
	})
	printed := 0
	for _, slot := range slots {
		if role == string(storagefirst.Participant) && slot.IdentityID != identity {
			continue
		}
		if printed == 0 {
			fmt.Fprintln(output, "relevant submission slots:")
		}
		fmt.Fprintf(output, "  %s %s/%d identity=%s attempt=%s status=%s manifest=%s\n",
			slot.Kind, slot.Phase, slot.Index, slot.IdentityID, slot.AttemptID, slot.Status, slot.ManifestKey)
		printed++
	}
	if printed == 0 {
		fmt.Fprintln(output, "relevant submission slots: none")
	}
}
