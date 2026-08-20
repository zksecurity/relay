package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

func runInitRoleConfig(args []string) error {
	set := flag.NewFlagSet("ceremony init-config", flag.ContinueOnError)
	var home, role, identity, phase, storagePath, coordinatorKey, ceremonyBinary string
	var signingKey, environment, enrollment, enrollmentSignature, out string
	set.StringVar(&home, "home", "", "absolute ceremony home containing public/, config/, and run/")
	set.StringVar(&role, "role", "", "participant, witness, mirror, auditor, or release")
	set.StringVar(&identity, "identity", "", "expected identity; verified and otherwise derived from authenticated material")
	set.StringVar(&phase, "phase", "phase1", "phase1 or phase2")
	set.StringVar(&storagePath, "storage", "", "coordinator-supplied relay-storage.json (default HOME/config/relay-storage.json)")
	set.StringVar(&coordinatorKey, "coordinator-key", "", "absolute path to the independently obtained coordinator public key")
	set.StringVar(&ceremonyBinary, "ceremony-binary", "mpc-ceremony", "trusted ceremony executable")
	set.StringVar(&signingKey, "signing-key", "", "participant-only absolute private-key path")
	set.StringVar(&environment, "environment", "", "participant-only absolute environment.json path")
	set.StringVar(&enrollment, "enrollment", "", "non-participant signed enrollment record")
	set.StringVar(&enrollmentSignature, "enrollment-signature", "", "non-participant enrollment signature")
	set.StringVar(&out, "out", "", "fresh role config (default HOME/config/ROLE-PHASE.json)")
	if err := set.Parse(args); err != nil {
		return err
	}
	if home == "" || role == "" || coordinatorKey == "" {
		return errors.New("--home, --role and --coordinator-key are required")
	}
	if role != access.RoleParticipant {
		if _, ok := ceremonyEnrollmentRole(role); !ok {
			return fmt.Errorf("unsupported configured role %q", role)
		}
	}
	if phase != "phase1" && phase != "phase2" {
		return errors.New("--phase must be phase1 or phase2")
	}
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return errors.New("--home must be an absolute clean path")
	}
	if storagePath == "" {
		storagePath = filepath.Join(home, "config", "relay-storage.json")
	}
	if out == "" {
		out = filepath.Join(home, "config", role+"-"+phase+".json")
	}
	for name, value := range map[string]string{
		"--storage": storagePath, "--coordinator-key": coordinatorKey, "--out": out,
	} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	storageConfig, err := loadStorageConfig(storagePath)
	if err != nil {
		return fmt.Errorf("load storage config: %w", err)
	}
	root := filepath.Join(home, "public")
	config := access.RoleConfig{
		Schema: access.RoleConfigSchema, Role: role, IdentityID: identity, Phase: phase,
		CeremonyID: storageConfig.CeremonyID, CeremonyHome: home, Root: root,
		Ceremony: filepath.Join(root, "ceremony.json"), CeremonySignature: filepath.Join(root, "ceremony.sig"),
		CoordinatorKey: coordinatorKey, CeremonyBinary: ceremonyBinary, RunRoot: filepath.Join(home, "run"),
		StorageConfig: storagePath, PublishedBaseURL: storageConfig.PublishedBaseURL,
		PublishedBucket: storageConfig.PublishedBucket,
	}
	inspector := transcript.Inspector{
		Executable: ceremonyBinary, CeremonyPath: config.Ceremony,
		CeremonySignaturePath: config.CeremonySignature, CoordinatorPublicKeyPath: coordinatorKey,
		TranscriptRoot: root,
	}
	definition, err := inspector.Definition()
	if err != nil {
		return fmt.Errorf("authenticate local ceremony: %w", err)
	}
	if definition.CeremonyID != storageConfig.CeremonyID {
		return errors.New("local ceremony does not match relay-storage.json")
	}
	if role == access.RoleParticipant {
		if signingKey == "" || environment == "" {
			return errors.New("participant config requires --signing-key and --environment")
		}
		if !filepath.IsAbs(signingKey) || filepath.Clean(signingKey) != signingKey ||
			!filepath.IsAbs(environment) || filepath.Clean(environment) != environment {
			return errors.New("--signing-key and --environment must be absolute clean paths")
		}
		participant, err := inspector.Participant(signingKey)
		if err != nil {
			return err
		}
		if identity != "" && identity != participant.ParticipantID {
			return fmt.Errorf("authenticated participant is %s, not %s", participant.ParticipantID, identity)
		}
		if phase == "phase1" && participant.Phase1Position == nil ||
			phase == "phase2" && participant.Phase2Position == nil {
			return fmt.Errorf("participant %s is not scheduled in %s", participant.ParticipantID, phase)
		}
		config.IdentityID = participant.ParticipantID
		config.SigningKey = signingKey
		config.Environment = environment
	} else {
		if enrollment == "" || enrollmentSignature == "" {
			return errors.New("non-participant config requires --enrollment and --enrollment-signature")
		}
		if !filepath.IsAbs(enrollment) || filepath.Clean(enrollment) != enrollment ||
			!filepath.IsAbs(enrollmentSignature) || filepath.Clean(enrollmentSignature) != enrollmentSignature {
			return errors.New("--enrollment and --enrollment-signature must be absolute clean paths")
		}
		inspection, err := inspector.Enrollment(enrollment, enrollmentSignature)
		if err != nil {
			return err
		}
		want, ok := ceremonyEnrollmentRole(role)
		if !ok || inspection.Role != want {
			return fmt.Errorf("authenticated enrollment role %q does not authorize relay role %q", inspection.Role, role)
		}
		if inspection.CeremonyID != config.CeremonyID {
			return errors.New("enrollment is for a different ceremony")
		}
		if identity != "" && identity != inspection.Identity.ID {
			return fmt.Errorf("authenticated enrollment identity is %s, not %s", inspection.Identity.ID, identity)
		}
		config.IdentityID = inspection.Identity.ID
		config.Enrollment = enrollment
		config.EnrollmentSignature = enrollmentSignature
	}
	if err := config.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(config.RunRoot, 0o700); err != nil {
		return err
	}
	if err := writeJSONNoReplace(out, config, 0o600); err != nil {
		return err
	}
	fmt.Printf("configured %s %s for %s\nprofile: %s\n", config.Role, config.IdentityID, config.Phase, out)
	return nil
}

func ceremonyEnrollmentRole(role string) (string, bool) {
	want := map[string]string{
		access.RoleWitness: "public-witness", access.RoleMirror: "mirror-operator",
		access.RoleAuditor: "auditor", access.RoleRelease: "release-signer",
	}
	value, ok := want[role]
	return value, ok
}

func loadRoleConfig(path string, expectedRole string) (access.RoleConfig, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return access.RoleConfig{}, err
	}
	if !info.Mode().IsRegular() {
		return access.RoleConfig{}, errors.New("role config must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return access.RoleConfig{}, errors.New("role config must not be accessible by group or other users")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return access.RoleConfig{}, err
	}
	config, err := access.Decode(raw, access.RoleConfig.Validate)
	if err != nil {
		return access.RoleConfig{}, err
	}
	if expectedRole != "" && config.Role != expectedRole {
		return access.RoleConfig{}, fmt.Errorf("configured role is %s, want %s", config.Role, expectedRole)
	}
	storageConfig, err := loadStorageConfig(config.StorageConfig)
	if err != nil {
		return access.RoleConfig{}, fmt.Errorf("load configured storage: %w", err)
	}
	if storageConfig.CeremonyID != config.CeremonyID ||
		storageConfig.PublishedBaseURL != config.PublishedBaseURL ||
		storageConfig.PublishedBucket != config.PublishedBucket {
		return access.RoleConfig{}, errors.New("role config does not match its relay-storage.json")
	}
	return config, nil
}

func configuredRoleOptions(config access.RoleConfig) roleOpts {
	return roleOpts{
		root: config.Root, definition: config.Ceremony, definitionSig: config.CeremonySignature,
		coordinatorKey: config.CoordinatorKey, ceremonyBinary: config.CeremonyBinary,
		phase: config.Phase, role: config.IdentityID,
		client:     store.Client{Bucket: config.PublishedBucket, PublicBaseURL: config.PublishedBaseURL, NoSign: true},
		signingKey: config.SigningKey, envPath: config.Environment,
		outDir: filepath.Join(config.RunRoot, "candidates"),
	}
}

func loadParticipantProfile(path string) (access.ParticipantConfig, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return access.ParticipantConfig{}, "", err
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return access.ParticipantConfig{}, "", err
	}
	if header.Schema == access.RoleConfigSchema {
		roleConfig, err := loadRoleConfig(path, access.RoleParticipant)
		if err != nil {
			return access.ParticipantConfig{}, "", err
		}
		return access.ParticipantConfig{
			Schema: access.ParticipantConfigSchema, Phase: roleConfig.Phase, Root: roleConfig.Root,
			Ceremony: roleConfig.Ceremony, CeremonySignature: roleConfig.CeremonySignature,
			CoordinatorKey: roleConfig.CoordinatorKey, CeremonyBinary: roleConfig.CeremonyBinary,
			SigningKey: roleConfig.SigningKey, Environment: roleConfig.Environment,
			CandidateParentDir: filepath.Join(roleConfig.RunRoot, "candidates"),
			PublishedBaseURL:   roleConfig.PublishedBaseURL, PublishedBucket: roleConfig.PublishedBucket,
		}, roleConfig.IdentityID, nil
	}
	participant, err := access.Decode(raw, access.ParticipantConfig.Validate)
	return participant, "", err
}

func hasNamedFlag(args []string, name string) bool {
	want := "--" + name
	for _, arg := range args {
		if arg == want || strings.HasPrefix(arg, want+"=") {
			return true
		}
	}
	return false
}
