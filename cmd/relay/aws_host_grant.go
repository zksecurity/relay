package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

const awsHostGrantEnvironment = "RELAY_AWS_HOST_GRANT_FILE"
const awsHostGrantValidationEnvironment = "RELAY_AWS_HOST_GRANT_VALIDATE"

type awsGrantRequest struct {
	Schema         string               `json:"schema"`
	Config         access.StorageConfig `json:"config"`
	Role           string               `json:"role"`
	IdentityID     string               `json:"identity_id"`
	Prefix         string               `json:"prefix"`
	TTLSeconds     int64                `json:"ttl_seconds"`
	Checkpoint     string               `json:"checkpoint_digest,omitempty"`
	SubmissionKind string               `json:"submission_kind,omitempty"`
	Phase          string               `json:"phase,omitempty"`
	Index          uint                 `json:"index,omitempty"`
	AttemptID      string               `json:"attempt_id,omitempty"`
}

type awsHostGrant struct {
	Schema      string                    `json:"schema"`
	Request     awsGrantRequest           `json:"request"`
	ExpiresAt   string                    `json:"expires_at"`
	Credentials access.SessionCredentials `json:"credentials"`
}

// prepareAWSHostGrant mints only the final prefix-scoped role session. The IAM
// user source remains in host AWS files. The trusted role image subsequently
// authenticates the ceremony request and accepts this session only when every
// independently derived field matches.
func prepareAWSHostGrant(ctx context.Context, b awsLoginBinding, dir string) error {
	if b.Schema != awsLoginSchemaV2 || !b.StaticIssuer || !strings.HasPrefix(b.Identity.Arn, "arn:aws:iam::"+b.Identity.Account+":user/") {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil || len(raw) > 1024*1024 {
		return errors.New("authenticated grant request was not produced")
	}
	var request awsGrantRequest
	if json.Unmarshal(raw, &request) != nil || request.Schema != "relay-aws-grant-request-v1" {
		return errors.New("invalid authenticated grant request")
	}
	config := request.Config
	if err := config.Validate(); err != nil || config.Provider != "aws" {
		return errors.New("invalid AWS storage in authenticated grant request")
	}
	if request.IdentityID == "" || request.Prefix == "" || request.TTLSeconds < 1 {
		return errors.New("invalid authenticated grant scope")
	}
	static, err := captureAWSStaticIssuer(ctx, b)
	if err != nil {
		return err
	}
	hostConfig := config
	hostConfig.IssuerProfile = b.Profile
	credentials, expires, err := issueAWSWithRunner(hostConfig, request.IdentityID, request.Prefix, time.Duration(request.TTLSeconds)*time.Second, func(args ...string) ([]byte, error) {
		// The issuer profile has already been captured and authenticated.
		// Captured-credential commands deliberately cannot read profile files.
		if len(args) < 2 || args[0] != "--profile" || args[1] != b.Profile {
			return nil, errors.New("unexpected issuer profile for host grant")
		}
		return awsLoginCommand(ctx, b, &static, args[2:]...)
	})
	if err != nil {
		return fmt.Errorf("issue exact scoped AWS grant from host IAM user: %w", err)
	}
	grant := awsHostGrant{Schema: "relay-aws-host-grant-v1", Request: request, ExpiresAt: expires.UTC().Format(time.RFC3339), Credentials: credentials}
	return saveJSONAtomic(filepath.Join(dir, "host-grant.json"), grant)
}

func captureAWSStaticIssuer(ctx context.Context, b awsLoginBinding) (awsProcessCredentials, error) {
	raw, err := awsLoginCommand(ctx, b, nil, "configure", "export-credentials", "--profile", b.Profile, "--format", "process")
	if err != nil {
		return awsProcessCredentials{}, err
	}
	credentials, err := parseAWSProcess(raw, time.Now(), 0)
	if err != nil || credentials.Expiration != "" || credentials.SessionToken != "" {
		return awsProcessCredentials{}, errAWSLoginInvalid
	}
	raw, err = awsLoginCommand(ctx, b, &credentials, "sts", "get-caller-identity", "--output", "json")
	if err != nil {
		return awsProcessCredentials{}, err
	}
	var identity awsLoginIdentity
	if json.Unmarshal(raw, &identity) != nil {
		return awsProcessCredentials{}, errAWSLoginInvalid
	}
	identity, err = normalizedAWSIdentity(identity)
	if err != nil || identity != b.Identity {
		return awsProcessCredentials{}, errAWSLoginInvalid
	}
	return credentials, nil
}

func consumeAWSHostGrant(config access.StorageConfig, identity, prefix string, ttl time.Duration) (access.SessionCredentials, time.Time, bool, error) {
	path := os.Getenv(awsHostGrantEnvironment)
	if path == "" {
		return access.SessionCredentials{}, time.Time{}, false, nil
	}
	if path != "/credentials/aws-login/host-grant.json" {
		return access.SessionCredentials{}, time.Time{}, true, errors.New("invalid host grant path")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64*1024 {
		return access.SessionCredentials{}, time.Time{}, true, errors.New("host-issued AWS grant is unavailable")
	}
	credentials, expires, err := decodeAWSHostGrant(raw, config, identity, prefix, ttl, time.Now())
	return credentials, expires, true, err
}

func decodeAWSHostGrant(raw []byte, config access.StorageConfig, identity, prefix string, ttl time.Duration, now time.Time) (access.SessionCredentials, time.Time, error) {
	var grant awsHostGrant
	if json.Unmarshal(raw, &grant) != nil || grant.Schema != "relay-aws-host-grant-v1" || grant.Request.Config.CeremonyID != config.CeremonyID || grant.Request.IdentityID != identity || grant.Request.Prefix != prefix || grant.Request.Config.GrantRoleARN != config.GrantRoleARN || grant.Request.Config.Region != config.Region || grant.Request.TTLSeconds != int64(ttl/time.Second) {
		return access.SessionCredentials{}, time.Time{}, errors.New("host-issued AWS grant does not match the authenticated request")
	}
	expires, err := time.Parse(time.RFC3339, grant.ExpiresAt)
	if err != nil || !expires.After(now.Add(awsLoginReserve)) || expires.After(now.Add(ttl+time.Minute)) {
		return access.SessionCredentials{}, time.Time{}, errors.New("host-issued AWS grant has an invalid lifetime")
	}
	if err := grant.Credentials.Validate(); err != nil || grant.Credentials.SessionToken == "" {
		return access.SessionCredentials{}, time.Time{}, errors.New("host-issued AWS grant has invalid temporary credentials")
	}
	return grant.Credentials, expires, nil
}

func validateAWSHostGrantRequest(request awsGrantRequest) error {
	path := os.Getenv(awsHostGrantEnvironment)
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64*1024 {
		return errors.New("host-issued AWS grant is unavailable")
	}
	return validateAWSHostGrantRequestBytes(raw, request)
}

func validateAWSHostGrantRequestBytes(raw []byte, request awsGrantRequest) error {
	var grant awsHostGrant
	if json.Unmarshal(raw, &grant) != nil || grant.Request != request {
		return errors.New("host-issued AWS grant does not match the authenticated request")
	}
	return nil
}
