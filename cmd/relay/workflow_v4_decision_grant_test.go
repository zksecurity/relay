package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func TestDecisionGrantPolicySeparatesPacketReadAndExactSignatureWrite(t *testing.T) {
	m := testDecisionHandoff(t)
	prefix, _ := workflowV4HandoffPrefix(m.CeremonyID, m.DecisionSHA256)
	signature, _ := workflowV4DecisionSignatureKey(m)
	for _, kind := range []string{"download", "upload"} {
		policy, err := workflowV4DecisionGrantPolicy("private-inbox", prefix, signature, kind)
		if err != nil {
			t.Fatal(err)
		}
		if len(policy) > 2048 || bytes.Contains(policy, []byte("published")) || bytes.Contains(policy, []byte("ListBucket")) || bytes.Contains(policy, []byte("DeleteObject")) {
			t.Fatalf("overbroad %s policy: %s", kind, policy)
		}
		var document struct {
			Statement []struct {
				Action   []string        `json:"Action"`
				Resource json.RawMessage `json:"Resource"`
			} `json:"Statement"`
		}
		if json.Unmarshal(policy, &document) != nil || len(document.Statement) != 1 {
			t.Fatal("invalid session policy")
		}
		statement := document.Statement[0]
		if kind == "download" {
			var resources []string
			if json.Unmarshal(statement.Resource, &resources) != nil || len(resources) != 2 || resources[0] != "arn:aws:s3:::private-inbox/"+prefix+"/manifest.json" || resources[1] != "arn:aws:s3:::private-inbox/"+prefix+"/objects/*" || slices.Contains(statement.Action, "s3:PutObject") {
				t.Fatalf("download grant can write or read outside packet: %s", policy)
			}
		} else {
			var resource string
			if json.Unmarshal(statement.Resource, &resource) != nil || resource != "arn:aws:s3:::private-inbox/"+signature || !slices.Contains(statement.Action, "s3:PutObject") || strings.Contains(resource, "*") {
				t.Fatalf("upload grant is not limited to exact signature: %s", policy)
			}
		}
	}
}

func TestDecisionGrantIssueAndPrivateFileValidation(t *testing.T) {
	m := testDecisionHandoff(t)
	config := access.StorageConfig{Provider: "aws", CeremonyID: m.CeremonyID, Region: "us-east-1", InboxBucket: "private-inbox", IssuerProfile: "issuer", GrantRoleARN: "arn:aws:iam::123456789012:role/inbox-grants", GrantRoleMaxTTL: "1h"}
	manifestSHA := testHandoffDigest("manifest")
	for _, kind := range []string{"download", "upload"} {
		expiry := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
		var called bool
		grant, err := workflowV4IssueDecisionGrantWithRunner(config, m, manifestSHA, kind, time.Hour, func(args ...string) ([]byte, error) {
			called = true
			joined := strings.Join(args, " ")
			if !strings.Contains(joined, "--profile issuer") || !strings.Contains(joined, "--role-arn "+config.GrantRoleARN) || !strings.Contains(joined, "--duration-seconds 3600") || !strings.Contains(joined, "--policy ") {
				t.Fatalf("wrong STS invocation: %s", joined)
			}
			return json.Marshal(map[string]any{"Credentials": map[string]string{"AccessKeyId": "TEMPACCESS", "SecretAccessKey": "TEMPSECRET", "SessionToken": "TEMPTOKEN", "Expiration": expiry.Format(time.RFC3339)}})
		})
		if err != nil || !called || grant.Kind != kind || grant.ManifestSHA256 != manifestSHA {
			t.Fatalf("issue %s: %v", kind, err)
		}
		path := filepath.Join(t.TempDir(), kind+".json")
		raw, _ := json.Marshal(grant)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := workflowV4LoadDecisionTransferGrant(path, kind, m.SignerID); err != nil {
			t.Fatal(err)
		}
		if _, err := workflowV4LoadDecisionTransferGrant(path, "other", m.SignerID); err == nil {
			t.Fatal("wrong grant purpose accepted")
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := workflowV4LoadDecisionTransferGrant(path, kind, m.SignerID); err == nil {
			t.Fatal("world-readable bearer grant accepted")
		}
	}
}

func TestDecisionGrantRejectsExpiredOrMismatchedBinding(t *testing.T) {
	m := testDecisionHandoff(t)
	now := time.Now().UTC().Truncate(time.Second)
	prefix, _ := workflowV4HandoffPrefix(m.CeremonyID, m.DecisionSHA256)
	signature, _ := workflowV4DecisionSignatureKey(m)
	g := workflowV4DecisionTransferGrant{Schema: workflowV4DecisionGrantSchema, Kind: "upload", CeremonyID: m.CeremonyID, CandidateID: m.CandidateID, CheckpointSHA256: m.CheckpointSHA256, DecisionSHA256: m.DecisionSHA256, ManifestSHA256: testHandoffDigest("manifest"), ManifestKey: prefix + "/manifest.json", SignatureKey: signature, SignerID: m.SignerID, Region: "us-east-1", InboxBucket: "private-inbox", IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Credentials: access.SessionCredentials{AccessKeyID: "A", SecretAccessKey: "B", SessionToken: "C"}}
	if err := g.validate(now); err != nil {
		t.Fatal(err)
	}
	changed := g
	changed.SignatureKey = prefix + "/signatures/other.sig"
	if changed.validate(now) == nil {
		t.Fatal("wrong signature scope accepted")
	}
	changed = g
	changed.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
	if changed.validate(now) == nil {
		t.Fatal("expired grant accepted")
	}
	changed = g
	changed.ManifestSHA256 = testHandoffDigest("other-manifest")
	if changed.validate(now) != nil {
		t.Fatal("grant format should accept a different digest; transport comparison must reject it")
	}
	transport := workflowV4SignerHandoffTransport{Schema: "relay-signer-decision-transport-v1", CeremonyID: g.CeremonyID, CandidateID: g.CandidateID, CheckpointSHA256: g.CheckpointSHA256, DecisionSHA256: g.DecisionSHA256, SignerID: g.SignerID, Region: g.Region, Bucket: g.InboxBucket, ManifestKey: g.ManifestKey, ManifestSHA256: g.ManifestSHA256, SignatureKey: g.SignatureKey}
	if workflowV4DecisionGrantMatchesTransport(changed, transport) {
		t.Fatal("changed manifest digest accepted for upload")
	}
	changed = g
	changed.SignerID = "release-*"
	changed.SignatureKey = prefix + "/signatures/release-*.sig"
	if changed.validate(now) == nil {
		t.Fatal("IAM wildcard in signer identity accepted")
	}
	changed = g
	changed.InboxBucket = "private-*"
	if changed.validate(now) == nil {
		t.Fatal("IAM wildcard in bucket accepted")
	}
}

func TestDecisionGrantMustStayOutsideSignerWork(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(root, "signer-work")
	if err := os.Mkdir(work, 0700); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4SignerGrantOutsideWork(filepath.Join(root, "grant.json"), work); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4SignerGrantOutsideWork(filepath.Join(work, "grant.json"), work); err == nil {
		t.Fatal("grant inside signer work would enter the offline signing mount")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(work, link); err != nil {
		t.Fatal(err)
	}
	if err := workflowV4SignerGrantOutsideWork(filepath.Join(link, "grant.json"), work); err == nil {
		t.Fatal("grant under symlink directory accepted")
	}
}
