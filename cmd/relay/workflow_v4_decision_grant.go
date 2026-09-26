package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

const workflowV4DecisionGrantSchema = "relay-decision-transfer-grant-v1"

// This is a bearer secret. It is delivered privately, never included in the
// public snapshot, decision evidence, diagnostics, or offline signer mounts.
type workflowV4DecisionTransferGrant struct {
	Schema           string                    `json:"schema"`
	Kind             string                    `json:"kind"`
	CeremonyID       string                    `json:"ceremony_id"`
	CandidateID      string                    `json:"candidate_id"`
	CheckpointSHA256 string                    `json:"checkpoint_sha256"`
	DecisionSHA256   string                    `json:"decision_sha256"`
	ManifestSHA256   string                    `json:"manifest_sha256"`
	ManifestKey      string                    `json:"manifest_key"`
	SignatureKey     string                    `json:"signature_key"`
	SignerID         string                    `json:"signer_id"`
	Region           string                    `json:"region"`
	InboxBucket      string                    `json:"inbox_bucket"`
	IssuedAt         string                    `json:"issued_at"`
	ExpiresAt        string                    `json:"expires_at"`
	Credentials      access.SessionCredentials `json:"credentials"`
}

func workflowV4DecisionSignatureKey(m workflowV4DecisionHandoff) (string, error) {
	prefix, err := workflowV4HandoffPrefix(m.CeremonyID, m.DecisionSHA256)
	if err != nil || !workflowV4SafeSignerID(m.SignerID) {
		return "", errors.New("invalid signer decision handoff scope")
	}
	return prefix + "/signatures/" + m.SignerID + ".sig", nil
}

func (g workflowV4DecisionTransferGrant) validate(now time.Time) error {
	if g.Schema != workflowV4DecisionGrantSchema || (g.Kind != "download" && g.Kind != "upload") {
		return errors.New("invalid decision transfer grant kind or schema")
	}
	for _, value := range []string{g.CeremonyID, g.CandidateID, g.CheckpointSHA256, g.DecisionSHA256, g.ManifestSHA256} {
		if _, err := workflowV4HandoffHex(value); err != nil {
			return err
		}
	}
	prefix, err := workflowV4HandoffPrefix(g.CeremonyID, g.DecisionSHA256)
	if err != nil || !workflowV4SafeSignerID(g.SignerID) ||
		g.ManifestKey != prefix+"/manifest.json" || g.SignatureKey != prefix+"/signatures/"+g.SignerID+".sig" {
		return errors.New("decision grant has an invalid exact object scope")
	}
	if !workflowV4SafeAWSBucket(g.InboxBucket) || g.Region == "" || strings.ContainsAny(g.Region, "/\\*?\x00\r\n \t") {
		return errors.New("decision grant has an invalid AWS destination")
	}
	issued, err := time.Parse(time.RFC3339, g.IssuedAt)
	if err != nil || issued.Location() != time.UTC || issued.After(now.Add(5*time.Minute)) {
		return errors.New("decision grant has an invalid issue time")
	}
	expires, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil || expires.Location() != time.UTC || !expires.After(now.Add(2*time.Minute)) || expires.Sub(issued) > access.MaxStorageFirstGrantLifetime+2*time.Minute {
		return errors.New("decision transfer grant is expired or exceeds its lifetime")
	}
	if err := g.Credentials.Validate(); err != nil {
		return err
	}
	return nil
}

func workflowV4SafeAWSBucket(bucket string) bool {
	edge := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	if len(bucket) < 3 || len(bucket) > 63 || !edge(bucket[0]) || !edge(bucket[len(bucket)-1]) {
		return false
	}
	for _, c := range bucket {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func workflowV4LoadDecisionTransferGrant(path, kind, signerID string) (workflowV4DecisionTransferGrant, error) {
	var grant workflowV4DecisionTransferGrant
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return grant, errors.New("private grant path must be absolute and clean")
	}
	raw, err := readTesseraRegularFile(path, 64<<10, true)
	if err != nil || rejectCommitJournalDuplicateFields(raw) != nil {
		return grant, errors.New("private decision grant must be a mode-0600 regular file with strict JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&grant) != nil || decoder.Decode(new(any)) != io.EOF || grant.Kind != kind || grant.SignerID != signerID {
		return grant, errors.New("private decision grant does not match the requested transfer and signer")
	}
	return grant, grant.validate(time.Now().UTC())
}

func workflowV4SignerGrantOutsideMounts(path string, mounts ...string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("private grant path must be absolute and clean")
	}
	if err := requireOfflineRealPath(filepath.Dir(path)); err != nil {
		return fmt.Errorf("private grant directory: %w", err)
	}
	for _, mount := range mounts {
		relative, err := filepath.Rel(mount, path)
		if err != nil || relative == "." || relative == ".." || !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("private grant must be outside all release-signer container mounts")
		}
	}
	return nil
}

func workflowV4DecisionGrantClient(g workflowV4DecisionTransferGrant) store.Client {
	credentials := store.Credentials{AccessKeyID: g.Credentials.AccessKeyID, SecretAccessKey: g.Credentials.SecretAccessKey, SessionToken: g.Credentials.SessionToken}
	return store.Client{Region: g.Region, Bucket: g.InboxBucket, Credentials: &credentials}
}

func workflowV4DecisionGrantPolicy(bucket, prefix, signatureKey, kind string) ([]byte, error) {
	base := "arn:aws:s3:::" + bucket + "/"
	statement := map[string]any{"Effect": "Allow"}
	if kind == "download" {
		statement["Action"] = []string{"s3:GetObject", "s3:GetObjectVersion"}
		statement["Resource"] = []string{base + prefix + "/manifest.json", base + prefix + "/objects/*"}
	} else if kind == "upload" {
		statement["Action"] = []string{"s3:PutObject", "s3:GetObject", "s3:GetObjectVersion"}
		statement["Resource"] = base + signatureKey
	} else {
		return nil, errors.New("unsupported decision grant kind")
	}
	policy, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{statement}})
	if err != nil || len(policy) > 2048 {
		return nil, errors.New("decision grant session policy exceeds AWS's bound")
	}
	return policy, nil
}

func workflowV4IssueDecisionGrantWithRunner(config access.StorageConfig, m workflowV4DecisionHandoff, manifestSHA, kind string, ttl time.Duration, run func(...string) ([]byte, error)) (workflowV4DecisionTransferGrant, error) {
	var grant workflowV4DecisionTransferGrant
	if err := m.validate(); err != nil {
		return grant, err
	}
	maximum, err := time.ParseDuration(config.GrantRoleMaxTTL)
	if err != nil || config.Provider != "aws" || config.CeremonyID != m.CeremonyID || !workflowV4SafeAWSBucket(config.InboxBucket) || config.Region == "" || config.IssuerProfile == "" || config.GrantRoleARN == "" || ttl < 15*time.Minute || ttl > maximum || ttl > access.MaxStorageFirstGrantLifetime {
		return grant, errors.New("decision grant requires matching AWS storage and an allowed lifetime")
	}
	if _, err := workflowV4HandoffHex(manifestSHA); err != nil {
		return grant, err
	}
	prefix, _ := workflowV4HandoffPrefix(m.CeremonyID, m.DecisionSHA256)
	signatureKey, err := workflowV4DecisionSignatureKey(m)
	if err != nil {
		return grant, err
	}
	policy, err := workflowV4DecisionGrantPolicy(config.InboxBucket, prefix, signatureKey, kind)
	if err != nil {
		return grant, err
	}
	issued := time.Now().UTC().Truncate(time.Second)
	session := "relay-decision-" + kind
	raw, err := run("--profile", config.IssuerProfile, "--region", config.Region,
		"sts", "assume-role", "--role-arn", config.GrantRoleARN,
		"--role-session-name", session, "--duration-seconds", strconv.FormatInt(int64(ttl/time.Second), 10),
		"--policy", string(policy), "--output", "json")
	if err != nil {
		return grant, fmt.Errorf("issue scoped decision transfer grant: %w", err)
	}
	var response struct {
		Credentials struct {
			AccessKeyID     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
			SessionToken    string `json:"SessionToken"`
			Expiration      string `json:"Expiration"`
		} `json:"Credentials"`
	}
	if json.Unmarshal(raw, &response) != nil {
		return grant, errors.New("AWS returned invalid decision grant credentials")
	}
	expires, err := time.Parse(time.RFC3339, response.Credentials.Expiration)
	if err != nil || !expires.After(time.Now().UTC().Add(2*time.Minute)) || expires.After(issued.Add(ttl+2*time.Minute)) {
		return grant, errors.New("AWS returned an invalid decision grant expiration")
	}
	grant = workflowV4DecisionTransferGrant{
		Schema: workflowV4DecisionGrantSchema, Kind: kind, CeremonyID: m.CeremonyID, CandidateID: m.CandidateID,
		CheckpointSHA256: m.CheckpointSHA256, DecisionSHA256: m.DecisionSHA256, ManifestSHA256: manifestSHA,
		ManifestKey: prefix + "/manifest.json", SignatureKey: signatureKey, SignerID: m.SignerID,
		Region: config.Region, InboxBucket: config.InboxBucket,
		IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.UTC().Format(time.RFC3339),
		Credentials: access.SessionCredentials{AccessKeyID: response.Credentials.AccessKeyID, SecretAccessKey: response.Credentials.SecretAccessKey, SessionToken: response.Credentials.SessionToken},
	}
	return grant, grant.validate(time.Now().UTC())
}

func runWorkflowV4IssueDecisionTransferGrant(ui *coordinatorWizard, online guidedProfile, protocol transcript.DefinitionProtocol, snapshot storagefirst.SnapshotV4) error {
	config, err := workflowV4HandoffConfig(online.Work, protocol.Definition.CeremonyID)
	if err != nil {
		return err
	}
	manifestPath := workflowV4HandoffManifestPath(online.Work)
	raw, err := readTesseraRegularFile(manifestPath, 16<<20, false)
	if err != nil {
		return errors.New("send and read back the completed decision packet before issuing a grant")
	}
	m, err := workflowV4DecodeHandoff(raw)
	if err != nil || m.CeremonyID != protocol.Definition.CeremonyID || m.CheckpointSHA256 != snapshot.Head().Record.Digest.SHA256 {
		return errors.New("retained decision packet differs from the authenticated final release")
	}
	expected, err := workflowV4ReleaseSignerAssignment(protocol)
	if err != nil || m.SignerID != expected.Identity.ID {
		return errors.New("decision grant signer differs from the authenticated assignment")
	}
	candidate, err := workflowV4CandidateID(snapshot, online.Work)
	if err != nil || candidate != m.CandidateID {
		return errors.New("decision grant candidate differs from the authenticated release")
	}
	decisionPath := filepath.Join(online.Work, "ceremony", "public", "decision", "decision.json")
	decisionSHA, _, err := workflowV4FileSHA256(decisionPath, 16<<20)
	if err != nil || decisionSHA != m.DecisionSHA256 {
		return errors.New("canonical decision differs from the completed AWS packet")
	}
	if err := workflowV4HandoffDecisionRelease(decisionPath, m.CandidateID, m.CheckpointSHA256, m.Snapshot.Root); err != nil {
		return err
	}
	manifestSHA, _, err := workflowV4FileSHA256(manifestPath, 16<<20)
	if err != nil {
		return err
	}
	prefix, _ := workflowV4HandoffPrefix(m.CeremonyID, m.DecisionSHA256)
	if err := workflowV4HandoffReadback(coordinatorClient(config, config.InboxBucket), prefix+"/manifest.json", manifestPath, filepath.Dir(manifestPath), 16<<20); err != nil {
		return fmt.Errorf("completed packet manifest is not retained in AWS: %w", err)
	}
	kind, err := ui.ask("Grant purpose: 1) Download packet  2) Upload signed public signature", "1")
	if err != nil {
		return err
	}
	switch kind {
	case "1":
		kind = "download"
	case "2":
		kind = "upload"
	default:
		return errors.New("choose download or upload grant")
	}
	maximum, err := workflowV4GrantTTL(config)
	if err != nil {
		return err
	}
	selected, err := ui.ask("Temporary grant lifetime (15m through "+maximum+")", "1h")
	if err != nil {
		return err
	}
	ttl, err := time.ParseDuration(selected)
	if err != nil || ttl < 15*time.Minute {
		return errors.New("invalid temporary grant lifetime")
	}
	fmt.Fprintf(ui.output, "Issue %s-only grant for ceremony %s, decision %s, signer %s. Previous grants may remain valid until their expiry. The private grant file must be delivered confidentially and kept out of the public archive.\n", kind, m.CeremonyID, m.DecisionSHA256, m.SignerID)
	if err := ui.confirm("Issue this exact temporary AWS grant", "ISSUE TEMPORARY GRANT"); err != nil {
		return err
	}
	grant, err := workflowV4IssueDecisionGrantWithRunner(config, m, manifestSHA, kind, ttl, func(args ...string) ([]byte, error) {
		command := exec.Command("aws", args...)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			return nil, fmt.Errorf("AWS STS assume-role: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	})
	if err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	// Role work is mounted into proof-tool containers. Keep bearer credentials
	// in the role's private parent directory instead.
	dir := filepath.Join(filepath.Dir(online.Work), "private-decision-grants")
	if err := workflowV4HandoffEnsureDir(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, kind+"-"+id+".json")
	encoded, err := json.Marshal(grant)
	if err != nil {
		return err
	}
	if err := setupWriteBytesNewOrExact(path, encoded, 0600); err != nil {
		return err
	}
	sha := sha256.Sum256(encoded)
	fmt.Fprintf(ui.output, "Private %s grant: %s\nGrant SHA-256: sha256:%s\nExpires: %s\nDeliver this file confidentially to the release signer. It must not enter the public snapshot, archive, diagnostics, or signing container.\n", kind, path, hex.EncodeToString(sha[:]), grant.ExpiresAt)
	return nil
}
