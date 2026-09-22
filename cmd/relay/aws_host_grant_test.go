package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func TestPrepareAWSHostGrantUsesStaticProfileAndScopedPolicy(t *testing.T) {
	config := access.StorageConfig{Schema: access.StorageConfigSchema, Provider: "aws", CeremonyID: "sha256:" + repeatHex("ab", 32), Region: "us-east-1", PublishedBucket: "public-fixture", PublishedBaseURL: "https://example.test", InboxBucket: "inbox-fixture", CoordinatorProfile: "relay-coordinator", IssuerProfile: "relay-coordinator", GrantRoleARN: "arn:aws:iam::123456789012:role/relay-grant", GrantRoleMaxTTL: "12h", CeremonyPath: "/work/ceremony.json", CeremonySignature: "/work/ceremony.sig", CoordinatorPublicKey: "/trust/coordinator.hex", CeremonyBinary: "mpc-ceremony"}
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	expires := time.Now().Add(12 * time.Hour).UTC().Format(time.RFC3339)
	script := "#!/bin/sh\nif test \"$1\" = configure; then\n printf '%s' '{\"Version\":1,\"AccessKeyId\":\"STATICACCESS\",\"SecretAccessKey\":\"STATICSECRET\"}'\nelif test \"$1\" = sts; then\n test \"$AWS_ACCESS_KEY_ID\" = STATICACCESS || exit 8\n printf '%s' '{\"Account\":\"123456789012\",\"Arn\":\"arn:aws:iam::123456789012:user/ceremony\",\"UserId\":\"AIDATEST\"}'\nelse\n test \"$AWS_ACCESS_KEY_ID\" = STATICACCESS || exit 9\n printf '%s\\n' \"$@\" > '" + argsPath + "'\n printf '%s' '{\"Credentials\":{\"AccessKeyId\":\"SCOPEDACCESS\",\"SecretAccessKey\":\"SCOPEDSECRET\",\"SessionToken\":\"SCOPEDTOKEN\",\"Expiration\":\"" + expires + "\"}}'\nfi\n"
	binary := filepath.Join(dir, "aws")
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	digest, err := awsBinaryDigest(binary)
	if err != nil {
		t.Fatal(err)
	}
	binding := awsLoginBinding{Schema: awsLoginSchemaV2, StaticIssuer: true, Binary: binary, SHA256: digest, Profile: "static-issuer", Region: "us-east-1", Config: filepath.Join(dir, "config"), Credentials: filepath.Join(dir, "credentials"), Cache: filepath.Join(dir, "cache"), Identity: awsLoginIdentity{Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/ceremony", UserId: "AIDATEST"}}
	runtime := t.TempDir()
	prefix, _ := access.Prefix(config.CeremonyID, access.RoleParticipant, "participant-01")
	request := awsGrantRequest{Schema: "relay-aws-grant-request-v1", Config: config, Role: "participant", IdentityID: "participant-01", Prefix: prefix, TTLSeconds: 43200}
	if err := saveJSONAtomic(filepath.Join(runtime, "request.json"), request); err != nil {
		t.Fatal(err)
	}
	if err := prepareAWSHostGrant(context.Background(), binding, runtime); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(args)
	if !strings.Contains(text, "static-issuer") || !strings.Contains(text, config.GrantRoleARN) || !strings.Contains(text, "arn:aws:s3:::inbox-fixture/") || strings.Contains(text, "arn:aws:s3:::public-fixture") {
		t.Fatalf("host assume-role was not exact and scoped: %s", text)
	}
	raw, err := os.ReadFile(filepath.Join(runtime, "host-grant.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeAWSHostGrant(raw, config, "participant-01", prefix, 12*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeAWSHostGrantRequiresExactRequest(t *testing.T) {
	config := access.StorageConfig{Provider: "aws", CeremonyID: "sha256:" + repeatHex("ab", 32), Region: "us-east-1", InboxBucket: "inbox-fixture", GrantRoleARN: "arn:aws:iam::123456789012:role/relay-grant"}
	expires := time.Now().Add(12 * time.Hour).UTC().Truncate(time.Second)
	request := awsGrantRequest{Schema: "relay-aws-grant-request-v1", Config: config, Role: "participant", IdentityID: "participant-01", Prefix: "scope/object", TTLSeconds: 43200}
	grant := awsHostGrant{Schema: "relay-aws-host-grant-v1", Request: request, ExpiresAt: expires.Format(time.RFC3339), Credentials: access.SessionCredentials{AccessKeyID: "ACCESS", SecretAccessKey: "SECRET", SessionToken: "TOKEN"}}
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	credentials, gotExpiry, err := decodeAWSHostGrant(raw, config, "participant-01", "scope/object", 12*time.Hour, time.Now())
	if err != nil || credentials.SessionToken != "TOKEN" || !gotExpiry.Equal(expires) {
		t.Fatalf("valid host grant rejected: %v", err)
	}
	if _, _, err := decodeAWSHostGrant(raw, config, "other", "scope/object", 12*time.Hour, time.Now()); err == nil {
		t.Fatal("accepted wrong identity")
	}
	if _, _, err := decodeAWSHostGrant(raw, config, "participant-01", "other", 12*time.Hour, time.Now()); err == nil {
		t.Fatal("accepted wrong prefix")
	}
}

func TestHostGrantSemanticRequestMustMatch(t *testing.T) {
	request := awsGrantRequest{Schema: "relay-aws-grant-request-v1", Role: "participant", IdentityID: "p", Prefix: "scope", TTLSeconds: 43200, Checkpoint: "sha256:" + repeatHex("a", 32), SubmissionKind: "candidate", Phase: "phase1", Index: 1, AttemptID: repeatHex("b", 16)}
	raw, _ := json.Marshal(awsHostGrant{Schema: "relay-aws-host-grant-v1", Request: request})
	for _, mutate := range []func(*awsGrantRequest){
		func(r *awsGrantRequest) { r.Phase = "phase2" },
		func(r *awsGrantRequest) { r.AttemptID = repeatHex("c", 16) },
		func(r *awsGrantRequest) { r.Checkpoint = "sha256:" + repeatHex("d", 32) },
	} {
		changed := request
		mutate(&changed)
		if validateAWSHostGrantRequestBytes(raw, changed) == nil {
			t.Fatal("accepted semantic request mismatch")
		}
	}
}

func TestHostGrantRequiresAuthenticatedRequestBeforeAWS(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "called")
	binary := filepath.Join(dir, "aws")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	digest, _ := awsBinaryDigest(binary)
	binding := awsLoginBinding{Schema: awsLoginSchemaV2, StaticIssuer: true, Binary: binary, SHA256: digest, Profile: "issuer", Region: "us-east-1", Config: filepath.Join(dir, "config"), Credentials: filepath.Join(dir, "credentials"), Cache: filepath.Join(dir, "cache"), Identity: awsLoginIdentity{Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/ceremony", UserId: "AIDATEST"}}
	if err := prepareAWSHostGrant(context.Background(), binding, dir); err == nil {
		t.Fatal("minted without authenticated request")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("AWS was called before authentication")
	}
}

func TestStaticIssuerIdentityMismatchStopsBeforeGrant(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "aws")
	script := "#!/bin/sh\nif test \"$1\" = configure; then printf '%s' '{\"Version\":1,\"AccessKeyId\":\"STATIC\",\"SecretAccessKey\":\"SECRET\"}'; else printf '%s' '{\"Account\":\"123456789012\",\"Arn\":\"arn:aws:iam::123456789012:user/other\",\"UserId\":\"AIDAOTHER\"}'; fi\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	digest, _ := awsBinaryDigest(binary)
	binding := awsLoginBinding{Schema: awsLoginSchemaV2, StaticIssuer: true, Binary: binary, SHA256: digest, Profile: "issuer", Region: "us-east-1", Config: filepath.Join(dir, "config"), Credentials: filepath.Join(dir, "credentials"), Cache: filepath.Join(dir, "cache"), Identity: awsLoginIdentity{Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/ceremony", UserId: "AIDATEST"}}
	if _, err := captureAWSStaticIssuer(context.Background(), binding); err == nil {
		t.Fatal("accepted changed issuer identity")
	}
}

func repeatHex(pair string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += pair
	}
	return result
}
