package access

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// GrantSchemaV2 adds an immutable storage-first submission scope. Grant and
	// GrantSchema remain the supported v1 format for existing ceremonies.
	GrantSchemaV2 = "relay-role-grant-v2"

	SubmissionKindCandidate  = "candidate"
	SubmissionKindEnrollment = "enrollment"
	SubmissionKindRelease    = "release"

	maxStorageFirstContributionIndex = 255
	// MaxStorageFirstGrantLifetime matches the longest AWS role session Relay
	// permits. Each ceremony may configure a shorter provider limit. Remaining
	// validity is measured against now, not against a self-written issued_at.
	MaxStorageFirstGrantLifetime  = 12 * time.Hour
	maxStorageFirstGrantClockSkew = 5 * time.Minute
	// Provider clocks and AssumeRole round-trip can place AWS Expiration a few
	// seconds past a full-hour request. This is not extra requested duration.
	maxStorageFirstGrantExpirySkew = 2 * time.Minute
)

// StorageFirstGrant is one temporary credential bound to one preallocated
// submission slot. It never grants authority merely because a prefix happens
// to contain similarly named objects.
type StorageFirstGrant struct {
	Schema           string             `json:"schema"`
	Provider         string             `json:"provider"`
	CeremonyID       string             `json:"ceremony_id"`
	GrantRequestID   string             `json:"grant_request_id"`
	CheckpointDigest string             `json:"checkpoint_digest"`
	SubmissionKind   string             `json:"submission_kind"`
	Phase            string             `json:"phase"`
	Index            uint8              `json:"index"`
	IdentityID       string             `json:"identity_id"`
	AttemptID        string             `json:"attempt_id"`
	Endpoint         string             `json:"endpoint,omitempty"`
	Region           string             `json:"region,omitempty"`
	InboxBucket      string             `json:"inbox_bucket"`
	Prefix           string             `json:"prefix"`
	ManifestKey      string             `json:"manifest_key"`
	IssuedAt         string             `json:"issued_at"`
	ExpiresAt        string             `json:"expires_at"`
	Credentials      SessionCredentials `json:"credentials"`
}

func (g StorageFirstGrant) Validate() error {
	if g.Schema != GrantSchemaV2 {
		return fmt.Errorf("grant schema %q, want %q", g.Schema, GrantSchemaV2)
	}
	if g.Provider != "r2" && g.Provider != "aws" {
		return errors.New("grant provider must be r2 or aws")
	}
	if g.Provider == "r2" {
		endpoint, err := url.Parse(g.Endpoint)
		if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return errors.New("R2 grant requires an HTTPS endpoint without credentials, query, or fragment")
		}
	} else if g.Region == "" || strings.TrimSpace(g.Region) != g.Region {
		return errors.New("AWS grant requires a region")
	}
	if !validHashID(g.CeremonyID) {
		return errors.New("grant ceremony_id is not a tagged SHA-256 digest")
	}
	if !validAttempt(g.GrantRequestID) {
		return errors.New("grant_request_id must be 16 bytes of lowercase hexadecimal")
	}
	if !validHashID(g.CheckpointDigest) {
		return errors.New("checkpoint_digest is not a tagged SHA-256 digest")
	}
	switch g.SubmissionKind {
	case SubmissionKindCandidate:
		if g.Phase != "phase1" && g.Phase != "phase2" {
			return errors.New("candidate grant phase must be phase1 or phase2")
		}
		if g.Index == 0 || g.Index > maxStorageFirstContributionIndex {
			return fmt.Errorf("candidate grant index must be between 1 and %d", maxStorageFirstContributionIndex)
		}
	case SubmissionKindEnrollment:
		if g.Phase != "setup" || g.Index == 0 || g.Index > 20 {
			return errors.New("enrollment grant requires setup phase and a role index between 1 and 20")
		}
	case SubmissionKindRelease:
		if g.Phase != "release" || g.Index != 1 {
			return errors.New("release grant requires release phase and index 1")
		}
	default:
		return errors.New("submission_kind must be candidate, enrollment or release")
	}
	if !validComponent(g.IdentityID) || !validComponent(g.InboxBucket) {
		return errors.New("grant identity or inbox bucket is invalid")
	}
	if !validAttempt(g.AttemptID) {
		return errors.New("attempt_id must be 16 bytes of lowercase hexadecimal")
	}
	if !validSubmissionPrefix(g.Prefix) {
		return errors.New("grant prefix must be a safe non-root relative prefix ending in slash")
	}
	if g.ManifestKey != g.Prefix+"manifest.json" || !validRelativeName(g.ManifestKey) {
		return errors.New("manifest_key must be exactly manifest.json within the granted prefix")
	}
	issued, err := parseCanonicalGrantTime("issued_at", g.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := parseCanonicalGrantTime("expires_at", g.ExpiresAt)
	if err != nil || !expires.After(issued) {
		return errors.New("expires_at must be canonical RFC3339 UTC and after issued_at")
	}
	return g.Credentials.Validate()
}

func StorageFirstGrantLifetime(provider string) time.Duration {
	if provider == "aws" {
		return MaxStorageFirstGrantLifetime
	}
	return time.Hour
}

func (g StorageFirstGrant) CheckUnexpired(now time.Time) error {
	if err := g.Validate(); err != nil {
		return err
	}
	issued, _ := time.Parse(time.RFC3339, g.IssuedAt)
	expires, _ := time.Parse(time.RFC3339, g.ExpiresAt)
	now = now.UTC()
	if issued.After(now.Add(maxStorageFirstGrantClockSkew)) {
		return fmt.Errorf("upload credentials are future-dated beyond the allowed %s clock skew", maxStorageFirstGrantClockSkew)
	}
	if !expires.After(now) {
		return fmt.Errorf("upload credentials expired at %s", g.ExpiresAt)
	}
	start := now
	if issued.After(start) {
		start = issued
	}
	maximum := StorageFirstGrantLifetime(g.Provider)
	if expires.Sub(start) > maximum+maxStorageFirstGrantExpirySkew {
		return fmt.Errorf("storage-first upload credentials may remain valid at most %s from now", maximum)
	}
	return nil
}

// ValidateRenewal permits fresh credentials only for the identical committed
// submission. A replacement contribution needs a new checkpoint slot instead.
func (g StorageFirstGrant) ValidateRenewal(previous StorageFirstGrant) error {
	if err := previous.Validate(); err != nil {
		return fmt.Errorf("previous grant: %w", err)
	}
	if err := g.Validate(); err != nil {
		return fmt.Errorf("renewed grant: %w", err)
	}
	if g.GrantRequestID == previous.GrantRequestID {
		return errors.New("renewal requires a new grant_request_id; retrying one request is idempotent, not renewal")
	}
	if g.Provider != previous.Provider || g.CeremonyID != previous.CeremonyID ||
		g.CheckpointDigest != previous.CheckpointDigest || g.SubmissionKind != previous.SubmissionKind ||
		g.Phase != previous.Phase || g.Index != previous.Index || g.IdentityID != previous.IdentityID ||
		g.AttemptID != previous.AttemptID || g.Endpoint != previous.Endpoint || g.Region != previous.Region ||
		g.InboxBucket != previous.InboxBucket || g.Prefix != previous.Prefix || g.ManifestKey != previous.ManifestKey {
		return errors.New("renewal changed the committed submission scope")
	}
	previousIssued, _ := time.Parse(time.RFC3339, previous.IssuedAt)
	issued, _ := time.Parse(time.RFC3339, g.IssuedAt)
	previousExpires, _ := time.Parse(time.RFC3339, previous.ExpiresAt)
	expires, _ := time.Parse(time.RFC3339, g.ExpiresAt)
	if issued.Before(previousIssued) || !expires.After(previousExpires) {
		return errors.New("renewal must not move issuance backward and must extend credential expiry")
	}
	return nil
}

func validSubmissionPrefix(value string) bool {
	if len(value) < 2 || len(value) > 512 || !strings.HasSuffix(value, "/") {
		return false
	}
	return validRelativeName(strings.TrimSuffix(value, "/"))
}

func parseCanonicalGrantTime(field, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || value != parsed.UTC().Format(time.RFC3339) {
		return time.Time{}, fmt.Errorf("%s must be canonical RFC3339 UTC", field)
	}
	return parsed, nil
}
