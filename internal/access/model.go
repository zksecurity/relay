// Package access defines the versioned, provider-neutral configuration and
// capability documents used by Relay's brokerless workflow.
package access

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	StorageConfigSchema       = "relay-storage-config-v1"
	GrantSchema               = "relay-role-grant-v1"
	ParticipantConfigSchemaV1 = "relay-participant-config-v1"
	ParticipantConfigSchemaV2 = "relay-participant-config-v2"
	ParticipantConfigSchema   = "relay-participant-config-v3"
	RoleConfigSchemaV1        = "relay-role-config-v1"
	RoleConfigSchema          = "relay-role-config-v2"
	CandidateManifestSchema   = "relay-candidate-manifest-v1"
	SubmissionManifestSchema  = "relay-evidence-submission-v1"
)

const (
	RoleParticipant = "participant"
	RoleWitness     = "witness"
	RoleMirror      = "mirror"
	RoleAuditor     = "auditor"
	RoleRelease     = "release"
	RoleDecision    = "decision"
)

type StorageConfig struct {
	Schema               string `json:"schema"`
	Provider             string `json:"provider"`
	CeremonyID           string `json:"ceremony_id"`
	Endpoint             string `json:"endpoint,omitempty"`
	Region               string `json:"region,omitempty"`
	AccountID            string `json:"account_id,omitempty"`
	ParentAccessKeyID    string `json:"parent_access_key_id,omitempty"`
	PublishedBucket      string `json:"published_bucket"`
	PublishedBaseURL     string `json:"published_base_url"`
	InboxBucket          string `json:"inbox_bucket"`
	CoordinatorProfile   string `json:"coordinator_profile"`
	IssuerProfile        string `json:"issuer_profile,omitempty"`
	GrantRoleARN         string `json:"grant_role_arn,omitempty"`
	GrantRoleMaxTTL      string `json:"grant_role_max_ttl,omitempty"`
	CeremonyPath         string `json:"ceremony"`
	CeremonySignature    string `json:"ceremony_signature"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
	CeremonyBinary       string `json:"ceremony_binary"`
}

func (c StorageConfig) Validate() error {
	if c.Schema != StorageConfigSchema {
		return fmt.Errorf("storage schema %q, want %q", c.Schema, StorageConfigSchema)
	}
	if c.Provider != "r2" && c.Provider != "aws" {
		return fmt.Errorf("storage provider %q must be r2 or aws", c.Provider)
	}
	if !validHashID(c.CeremonyID) {
		return errors.New("storage ceremony_id is not a tagged SHA-256 digest")
	}
	if c.PublishedBucket == "" || c.InboxBucket == "" || c.PublishedBucket == c.InboxBucket {
		return errors.New("distinct published_bucket and inbox_bucket are required")
	}
	if c.CoordinatorProfile == "" || c.CeremonyPath == "" || c.CeremonySignature == "" ||
		c.CoordinatorPublicKey == "" || c.CeremonyBinary == "" {
		return errors.New("storage coordinator profile and ceremony trust paths are required")
	}
	base, err := url.Parse(c.PublishedBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("published_base_url must be an HTTPS origin without query or fragment")
	}
	if c.Provider == "r2" {
		endpoint, err := url.Parse(c.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" ||
			c.AccountID == "" || c.ParentAccessKeyID == "" {
			return errors.New("R2 storage requires account_id, parent_access_key_id, and an HTTPS endpoint")
		}
	} else {
		if c.Region == "" || c.GrantRoleARN == "" || c.IssuerProfile == "" {
			return errors.New("AWS storage requires region, issuer_profile, and grant_role_arn")
		}
		maximum, err := time.ParseDuration(c.GrantRoleMaxTTL)
		if err != nil || maximum < time.Hour || maximum > 12*time.Hour {
			return errors.New("AWS grant_role_max_ttl must be between 1h and 12h")
		}
	}
	return nil
}

type SessionCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func (c SessionCredentials) Validate() error {
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" {
		return errors.New("temporary access key, secret, and session token are required")
	}
	return nil
}

type Grant struct {
	Schema           string             `json:"schema"`
	Provider         string             `json:"provider"`
	CeremonyID       string             `json:"ceremony_id"`
	Role             string             `json:"role"`
	IdentityID       string             `json:"identity_id"`
	Endpoint         string             `json:"endpoint,omitempty"`
	Region           string             `json:"region,omitempty"`
	InboxBucket      string             `json:"inbox_bucket"`
	Prefix           string             `json:"prefix"`
	IssuedAt         string             `json:"issued_at"`
	ExpiresAt        string             `json:"expires_at"`
	MinimumRemaining string             `json:"minimum_remaining"`
	Credentials      SessionCredentials `json:"credentials"`
}

func (g Grant) Validate() error {
	if g.Schema != GrantSchema {
		return fmt.Errorf("grant schema %q, want %q", g.Schema, GrantSchema)
	}
	if g.Provider != "r2" && g.Provider != "aws" {
		return errors.New("grant provider must be r2 or aws")
	}
	if g.Provider == "r2" {
		endpoint, err := url.Parse(g.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
			return errors.New("R2 grant requires an HTTPS endpoint")
		}
	} else if g.Region == "" {
		return errors.New("AWS grant requires a region")
	}
	if !validHashID(g.CeremonyID) || !validComponent(g.IdentityID) || g.InboxBucket == "" {
		return errors.New("grant ceremony, identity, or inbox bucket is invalid")
	}
	want, err := Prefix(g.CeremonyID, g.Role, g.IdentityID)
	if err != nil {
		return err
	}
	if g.Prefix != want {
		return fmt.Errorf("grant prefix %q, want %q", g.Prefix, want)
	}
	issued, err := time.Parse(time.RFC3339, g.IssuedAt)
	if err != nil {
		return errors.New("grant issued_at must be RFC3339 UTC")
	}
	expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return errors.New("grant expires_at must be after issued_at")
	}
	minimum, err := time.ParseDuration(g.MinimumRemaining)
	if err != nil || minimum <= 0 || expires.Sub(issued) < minimum {
		return errors.New("grant minimum_remaining must be positive and no greater than its lifetime")
	}
	return g.Credentials.Validate()
}

func (g Grant) CheckUsable(now time.Time) error {
	if err := g.CheckUnexpired(now); err != nil {
		return err
	}
	expires, _ := time.Parse(time.RFC3339, g.ExpiresAt)
	minimum, _ := time.ParseDuration(g.MinimumRemaining)
	remaining := expires.Sub(now.UTC())
	if remaining < minimum {
		return fmt.Errorf("upload credentials expire in %s, but at least %s are required; ask the coordinator to renew your access before continuing", remaining.Round(time.Minute), minimum)
	}
	return nil
}

// CheckUnexpired is used after expensive local work has completed. At that
// point requiring the original minimum window again would incorrectly reject
// a healthy run; only enough lifetime to finish the upload is required.
func (g Grant) CheckUnexpired(now time.Time) error {
	if err := g.Validate(); err != nil {
		return err
	}
	expires, _ := time.Parse(time.RFC3339, g.ExpiresAt)
	if !expires.After(now.UTC()) {
		return fmt.Errorf("upload credentials expired at %s", g.ExpiresAt)
	}
	return nil
}

func Prefix(ceremonyID, role, identity string) (string, error) {
	if !validHashID(ceremonyID) || !validComponent(identity) {
		return "", errors.New("invalid ceremony or identity for grant prefix")
	}
	id := strings.TrimPrefix(ceremonyID, "sha256:")
	var root string
	switch role {
	case RoleParticipant:
		root = "candidates"
	case RoleWitness:
		root = "operational/witnesses"
	case RoleMirror:
		root = "operational/mirrors"
	case RoleAuditor:
		root = "audits"
	case RoleRelease:
		root = "releases"
	case RoleDecision:
		root = "decisions"
	default:
		return "", fmt.Errorf("unsupported grant role %q", role)
	}
	return root + "/" + id + "/" + identity + "/", nil
}

type ParticipantConfig struct {
	Schema             string `json:"schema"`
	Phase              string `json:"phase"`
	Root               string `json:"root"`
	Ceremony           string `json:"ceremony"`
	CeremonySignature  string `json:"ceremony_signature"`
	CoordinatorKey     string `json:"coordinator_key"`
	CeremonyBinary     string `json:"ceremony_binary"`
	SigningKey         string `json:"signing_key"`
	Environment        string `json:"environment"`
	CandidateParentDir string `json:"candidate_parent_dir"`
	PublishedBaseURL   string `json:"published_base_url"`
	PublishedBucket    string `json:"published_bucket"`
	GrantPath          string `json:"grant_path,omitempty"`
	ExecutionMode      string `json:"execution_mode,omitempty"`
	DockerImage        string `json:"docker_image,omitempty"`
	DockerPlatform     string `json:"docker_platform,omitempty"`
	DockerCLI          string `json:"docker_cli,omitempty"`
}

// RoleConfig is the persistent, non-secret production profile for one
// ceremony role. It records paths to trust and key material but never embeds
// private key bytes, cloud credentials, or temporary upload grants.
type RoleConfig struct {
	Schema              string `json:"schema"`
	Role                string `json:"role"`
	IdentityID          string `json:"identity_id"`
	Phase               string `json:"phase"`
	CeremonyID          string `json:"ceremony_id"`
	CeremonyHome        string `json:"ceremony_home"`
	Root                string `json:"root"`
	Ceremony            string `json:"ceremony"`
	CeremonySignature   string `json:"ceremony_signature"`
	CoordinatorKey      string `json:"coordinator_key"`
	CeremonyBinary      string `json:"ceremony_binary"`
	SigningKey          string `json:"signing_key,omitempty"`
	Environment         string `json:"environment,omitempty"`
	Enrollment          string `json:"enrollment,omitempty"`
	EnrollmentSignature string `json:"enrollment_signature,omitempty"`
	RunRoot             string `json:"run_root"`
	StorageConfig       string `json:"storage_config"`
	PublishedBaseURL    string `json:"published_base_url"`
	PublishedBucket     string `json:"published_bucket"`
	ExecutionMode       string `json:"execution_mode,omitempty"`
	DockerImage         string `json:"docker_image,omitempty"`
	DockerPlatform      string `json:"docker_platform,omitempty"`
	DockerCLI           string `json:"docker_cli,omitempty"`
}

func (c RoleConfig) Validate() error {
	if c.Schema != RoleConfigSchemaV1 && c.Schema != RoleConfigSchema {
		return fmt.Errorf("role config schema %q is unsupported", c.Schema)
	}
	if c.Role != RoleParticipant && c.Role != RoleWitness && c.Role != RoleMirror &&
		c.Role != RoleAuditor && c.Role != RoleRelease {
		return fmt.Errorf("unsupported configured role %q", c.Role)
	}
	if !validComponent(c.IdentityID) || !validHashID(c.CeremonyID) ||
		(c.Phase != "phase1" && c.Phase != "phase2") {
		return errors.New("role config has an invalid identity, ceremony, or phase")
	}
	for name, value := range map[string]string{
		"ceremony_home": c.CeremonyHome, "root": c.Root, "ceremony": c.Ceremony,
		"ceremony_signature": c.CeremonySignature, "coordinator_key": c.CoordinatorKey,
		"run_root": c.RunRoot, "storage_config": c.StorageConfig,
	} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("role config %s must be an absolute clean path", name)
		}
	}
	if c.CeremonyBinary == "" {
		return errors.New("role config ceremony_binary is required")
	}
	if err := validateExecution(c.Schema == RoleConfigSchema, c.Role, c.ExecutionMode, c.CeremonyBinary,
		c.DockerImage, c.DockerPlatform, c.DockerCLI); err != nil {
		return fmt.Errorf("role config execution: %w", err)
	}
	if c.Role == RoleParticipant {
		if c.SigningKey == "" || c.Environment == "" ||
			!filepath.IsAbs(c.SigningKey) || filepath.Clean(c.SigningKey) != c.SigningKey ||
			!filepath.IsAbs(c.Environment) || filepath.Clean(c.Environment) != c.Environment {
			return errors.New("participant role config requires absolute signing_key and environment paths")
		}
		if c.Enrollment != "" || c.EnrollmentSignature != "" {
			return errors.New("participant role config must not contain operational enrollment paths")
		}
	} else {
		if c.Enrollment == "" || c.EnrollmentSignature == "" ||
			!filepath.IsAbs(c.Enrollment) || filepath.Clean(c.Enrollment) != c.Enrollment ||
			!filepath.IsAbs(c.EnrollmentSignature) || filepath.Clean(c.EnrollmentSignature) != c.EnrollmentSignature {
			return errors.New("non-participant role config requires absolute enrollment paths")
		}
		if c.SigningKey != "" || c.Environment != "" {
			return errors.New("non-participant role config must not retain signing-key or environment paths")
		}
	}
	base, err := url.Parse(c.PublishedBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("role config published_base_url must be an HTTPS origin")
	}
	if c.PublishedBucket == "" {
		return errors.New("role config published_bucket is required")
	}
	return nil
}

func (c ParticipantConfig) Validate() error {
	if (c.Schema != ParticipantConfigSchemaV1 && c.Schema != ParticipantConfigSchemaV2 && c.Schema != ParticipantConfigSchema) ||
		(c.Phase != "phase1" && c.Phase != "phase2") {
		return errors.New("participant config has invalid schema or phase")
	}
	for name, value := range map[string]string{
		"root": c.Root, "ceremony": c.Ceremony, "ceremony_signature": c.CeremonySignature,
		"coordinator_key": c.CoordinatorKey, "ceremony_binary": c.CeremonyBinary,
		"signing_key": c.SigningKey, "environment": c.Environment,
		"candidate_parent_dir": c.CandidateParentDir, "published_base_url": c.PublishedBaseURL,
		"published_bucket": c.PublishedBucket,
	} {
		if value == "" {
			return fmt.Errorf("participant config %s is required", name)
		}
	}
	if c.Schema == ParticipantConfigSchemaV1 && c.GrantPath == "" {
		return errors.New("participant config grant_path is required for v1")
	}
	if err := validateExecution(c.Schema == ParticipantConfigSchema, RoleParticipant, c.ExecutionMode,
		c.CeremonyBinary, c.DockerImage, c.DockerPlatform, c.DockerCLI); err != nil {
		return fmt.Errorf("participant config execution: %w", err)
	}
	base, err := url.Parse(c.PublishedBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("participant config published_base_url must be an HTTPS origin")
	}
	return nil
}

func validateExecution(latest bool, role, mode, ceremonyBinary, image, platform, dockerCLI string) error {
	if mode == "" {
		mode = "native"
	}
	if mode != "native" && mode != "docker" {
		return errors.New("execution_mode must be native or docker")
	}
	if mode == "native" {
		if image != "" || platform != "" || dockerCLI != "" {
			return errors.New("native execution must not contain Docker settings")
		}
		return nil
	}
	if role != RoleParticipant {
		return errors.New("Docker execution is currently supported only for participants")
	}
	if !latest {
		return errors.New("Docker execution requires the latest configuration schema")
	}
	if !filepath.IsAbs(ceremonyBinary) || filepath.Clean(ceremonyBinary) != ceremonyBinary {
		return errors.New("Docker ceremony_binary must be an absolute clean container path")
	}
	if !pinnedDockerImage(image) {
		return errors.New("docker_image must be an immutable sha256 image ID or repository@sha256 digest")
	}
	if platform != "linux/amd64" && platform != "linux/arm64" {
		return errors.New("docker_platform must be linux/amd64 or linux/arm64")
	}
	if dockerCLI == "" {
		return errors.New("docker_cli is required for Docker execution")
	}
	return nil
}

func pinnedDockerImage(image string) bool {
	if strings.HasPrefix(image, "sha256:") && len(image) == len("sha256:")+64 {
		_, err := hex.DecodeString(strings.TrimPrefix(image, "sha256:"))
		return err == nil
	}
	const marker = "@sha256:"
	index := strings.LastIndex(image, marker)
	if index <= 0 || len(image) != index+len(marker)+64 {
		return false
	}
	_, err := hex.DecodeString(image[index+len(marker):])
	return err == nil
}

type FileRef struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func (r FileRef) Validate() error {
	if !validRelativeName(r.Name) || !validHashID(r.SHA256) || r.Size < 0 {
		return fmt.Errorf("invalid submitted file reference %q", r.Name)
	}
	return nil
}

type CandidateManifest struct {
	Schema            string    `json:"schema"`
	CeremonyID        string    `json:"ceremony_id"`
	Phase             string    `json:"phase"`
	Index             int       `json:"index"`
	ParticipantID     string    `json:"participant_id"`
	ParentChainSHA256 string    `json:"parent_chain_sha256"`
	AttemptID         string    `json:"attempt_id"`
	Files             []FileRef `json:"files"`
	CompletedAt       string    `json:"completed_at"`
}

func (m CandidateManifest) Validate() error {
	if m.Schema != CandidateManifestSchema || !validHashID(m.CeremonyID) ||
		(m.Phase != "phase1" && m.Phase != "phase2") || m.Index < 1 ||
		!validComponent(m.ParticipantID) || !validHashID(m.ParentChainSHA256) ||
		!validAttempt(m.AttemptID) || len(m.Files) != 5 {
		return errors.New("candidate manifest identity or scope is invalid")
	}
	wanted := map[string]bool{"contribution.bin": false, "attestation.json": false, "attestation.sig": false, "erasure.json": false, "erasure.sig": false}
	for _, file := range m.Files {
		if err := file.Validate(); err != nil {
			return err
		}
		if _, ok := wanted[file.Name]; !ok || wanted[file.Name] {
			return fmt.Errorf("candidate file %q is unexpected or duplicated", file.Name)
		}
		wanted[file.Name] = true
	}
	if _, err := time.Parse(time.RFC3339, m.CompletedAt); err != nil {
		return errors.New("candidate completed_at must be RFC3339")
	}
	return nil
}

type SubmissionManifest struct {
	Schema      string    `json:"schema"`
	CeremonyID  string    `json:"ceremony_id"`
	Role        string    `json:"role"`
	IdentityID  string    `json:"identity_id"`
	AttemptID   string    `json:"attempt_id"`
	Files       []FileRef `json:"files"`
	CompletedAt string    `json:"completed_at"`
}

func (m SubmissionManifest) Validate() error {
	if m.Schema != SubmissionManifestSchema || !validHashID(m.CeremonyID) ||
		!validComponent(m.IdentityID) || !validAttempt(m.AttemptID) || len(m.Files) == 0 {
		return errors.New("evidence submission identity or scope is invalid")
	}
	if _, err := Prefix(m.CeremonyID, m.Role, m.IdentityID); err != nil || m.Role == RoleParticipant {
		return errors.New("evidence submission role is invalid")
	}
	seen := map[string]struct{}{}
	for _, file := range m.Files {
		if err := file.Validate(); err != nil {
			return err
		}
		if _, ok := seen[file.Name]; ok {
			return fmt.Errorf("evidence file %q is duplicated", file.Name)
		}
		seen[file.Name] = struct{}{}
	}
	if _, err := time.Parse(time.RFC3339, m.CompletedAt); err != nil {
		return errors.New("evidence completed_at must be RFC3339")
	}
	return nil
}

func Decode[T any](raw []byte, validate func(T) error) (T, error) {
	var value T
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return value, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return value, errors.New("document contains trailing JSON data")
	}
	return value, validate(value)
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("JSON object contains a non-string key")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("JSON object contains duplicate field %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("document contains trailing JSON data")
		}
		return err
	}
	return nil
}

func validHashID(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func validComponent(value string) bool {
	return value != "" && len(value) <= 128 && path.Base(value) == value &&
		value != "." && value != ".." && !strings.ContainsAny(value, `/\\`)
}

func validRelativeName(value string) bool {
	return value != "" && len(value) <= 512 && path.Clean(value) == value &&
		!strings.HasPrefix(value, "/") && value != "." && value != ".." &&
		!strings.HasPrefix(value, "../") && !strings.Contains(value, `\`)
}

func validAttempt(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range value {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}
