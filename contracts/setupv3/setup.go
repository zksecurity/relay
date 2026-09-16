// Package setupv3 defines the public website/CLI setup contract. Validation here
// checks structure and consistency, not protocol signatures or release provenance.
package setupv3

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const MaxBytes = 8 * 1024 * 1024

//go:embed schema.json
var SchemaJSON []byte

//go:embed ruleset.json
var RulesetJSON []byte

//go:embed beacon.json
var BeaconJSON []byte

const (
	DefaultRehearsalBeaconLeadSeconds  uint32 = 180
	DefaultProductionBeaconLeadSeconds uint32 = 24 * 60 * 60
)

func Beacon(mode string, selectedLead ...uint32) map[string]any {
	var b map[string]any
	if err := json.Unmarshal(BeaconJSON, &b); err != nil {
		panic(err)
	}
	lead := DefaultRehearsalBeaconLeadSeconds
	if mode == "production" {
		lead = DefaultProductionBeaconLeadSeconds
	}
	if len(selectedLead) == 1 {
		lead = selectedLead[0]
	} else if len(selectedLead) > 1 {
		panic("Beacon accepts at most one selected lead")
	}
	b["minimum_witness_lead_seconds"] = float64(lead)
	return b
}

type Identity struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"ed25519_public_key_hex"`
	Fingerprint string `json:"public_key_fingerprint"`
}
type Role struct {
	ID         string `json:"id"`
	Role       string `json:"role"`
	IdentityID string `json:"identity_id"`
}
type Phase struct {
	ID          string   `json:"id"`
	IdentityIDs []string `json:"identity_ids"`
	Minimum     int      `json:"minimum"`
}
type Ruleset struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}
type Software struct {
	ReleaseTag           string `json:"release_tag"`
	CLICommit            string `json:"cli_commit"`
	ProofToolCommit      string `json:"proof_tool_commit"`
	ManifestSHA256       string `json:"manifest_sha256"`
	WorkflowRecipeSHA256 string `json:"workflow_recipe_sha256"`
}
type Storage struct {
	Provider        string `json:"provider"`
	Region          string `json:"region"`
	PublicBaseURL   string `json:"public_base_url"`
	PublishedBucket string `json:"published_bucket"`
	InboxBucket     string `json:"inbox_bucket"`
}
type AssurancePolicy struct {
	PublicWitnessesPerPhase       int `json:"public_witnesses_per_phase"`
	MirrorsPerAcceptedHead        int `json:"mirrors_per_accepted_head"`
	PassingCeremonyAudits         int `json:"passing_ceremony_audits"`
	ExternalSecurityAuditSignoffs int `json:"external_security_audit_signoffs"`
}
type Plan struct {
	Mode            string          `json:"mode"`
	Ruleset         Ruleset         `json:"ruleset"`
	Circuit         string          `json:"circuit"`
	BeaconPolicy    map[string]any  `json:"beacon_policy"`
	SoftwareRelease Software        `json:"software_release"`
	Storage         Storage         `json:"storage"`
	AssurancePolicy AssurancePolicy `json:"assurance_policy"`
	Identities      []Identity      `json:"identities"`
	Roles           []Role          `json:"roles"`
	Phases          []Phase         `json:"phases"`
}
type Artifact struct {
	Kind       string `json:"kind"`
	Platform   string `json:"platform"`
	SHA256     string `json:"sha256"`
	ByteLength int    `json:"byte_length"`
	ContentB64 string `json:"content_b64"`
}
type Result struct {
	InputSHA256 string     `json:"input_sha256"`
	ProtocolID  string     `json:"protocol_id"`
	Artifacts   []Artifact `json:"artifacts"`
}
type Setup struct {
	Schema       string  `json:"schema"`
	ID           string  `json:"id"`
	PlanRevision int     `json:"plan_revision"`
	Plan         Plan    `json:"plan"`
	Result       *Result `json:"result"`
}

func Hash(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
func Canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return jsoncanonicalizer.Transform(b)
}
func Digest(domain string, v any) (string, error) {
	b, e := Canonical(v)
	if e != nil {
		return "", e
	}
	return Hash(append([]byte(domain+"\n"), b...)), nil
}
func (s Setup) InputDigest() (string, error) {
	return Digest("ceremony-setup-input-v3", map[string]any{"schema": s.Schema, "id": s.ID, "plan_revision": s.PlanRevision, "plan": s.Plan})
}
func (s Setup) Digest() (string, error)  { return Digest("ceremony-setup-v3", s) }
func (r Result) Digest() (string, error) { return Digest("ceremony-setup-result-v3", r) }
func Rules() Ruleset {
	b, e := jsoncanonicalizer.Transform(RulesetJSON)
	if e != nil {
		panic(e)
	}
	return Ruleset{"two-phase-v3", 3, Hash(b)}
}

var compiled = sync.OnceValues(func() (*jsonschema.Schema, error) {
	var v any
	if e := json.Unmarshal(SchemaJSON, &v); e != nil {
		return nil, e
	}
	c := jsonschema.NewCompiler()
	if e := c.AddResource("setup.json", v); e != nil {
		return nil, e
	}
	return c.Compile("setup.json")
})

func depth(v any, n int) error {
	if n > 16 {
		return fmt.Errorf("JSON nesting exceeds 16")
	}
	switch x := v.(type) {
	case map[string]any:
		for _, v := range x {
			if e := depth(v, n+1); e != nil {
				return e
			}
		}
	case []any:
		for _, v := range x {
			if e := depth(v, n+1); e != nil {
				return e
			}
		}
	}
	return nil
}
func Parse(raw []byte) (*Setup, error) {
	if len(raw) > MaxBytes {
		return nil, fmt.Errorf("setup exceeds 8 MiB")
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("setup is not UTF-8")
	}
	// Bound nesting before the canonicalizer's recursive parser runs.
	d := json.NewDecoder(bytes.NewReader(raw))
	nesting := 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if t, ok := token.(json.Delim); ok {
			if t == '{' || t == '[' {
				nesting++
				if nesting > 16 {
					return nil, fmt.Errorf("JSON nesting exceeds 16")
				}
			} else {
				nesting--
			}
		}
	}
	// JCS rejects duplicate keys, invalid UTF-8, and lone Unicode surrogates.
	canonical, e := jsoncanonicalizer.Transform(raw)
	if e != nil {
		return nil, fmt.Errorf("invalid setup JSON: %w", e)
	}
	var value any
	if e = json.Unmarshal(canonical, &value); e != nil {
		return nil, e
	}
	if e = depth(value, 0); e != nil {
		return nil, e
	}
	schema, e := compiled()
	if e != nil {
		return nil, e
	}
	if e = schema.Validate(value); e != nil {
		return nil, fmt.Errorf("setup schema: %w", e)
	}
	var s Setup
	if e = json.Unmarshal(canonical, &s); e != nil {
		return nil, e
	}
	if e = s.validate(); e != nil {
		return nil, e
	}
	return &s, nil
}
func (s Setup) Validate() error {
	b, e := json.Marshal(s)
	if e != nil {
		return e
	}
	_, e = Parse(b)
	return e
}

func (s Setup) validate() error {
	p := s.Plan
	lead, ok := p.BeaconPolicy["minimum_witness_lead_seconds"].(float64)
	if !ok || lead < 1 || lead > float64(^uint32(0)) || lead != float64(uint32(lead)) {
		return fmt.Errorf("beacon lead must be a positive whole number of seconds")
	}
	expectedBeacon, _ := Canonical(Beacon(p.Mode, uint32(lead)))
	actualBeacon, _ := Canonical(p.BeaconPolicy)
	if !bytes.Equal(expectedBeacon, actualBeacon) {
		return fmt.Errorf("beacon policy must match the approved profile for this mode")
	}
	if p.Ruleset != Rules() {
		return fmt.Errorf("unsupported ruleset digest")
	}
	if p.Mode == "production" && p.Circuit == "rehearsal-tiny-v1" {
		return fmt.Errorf("tiny circuit is rehearsal only")
	}
	if p.SoftwareRelease.ReleaseTag != "role-images-"+p.SoftwareRelease.CLICommit {
		return fmt.Errorf("release tag does not match CLI commit")
	}
	if p.Storage.PublishedBucket == p.Storage.InboxBucket {
		return fmt.Errorf("published and inbox buckets must differ")
	}
	u, e := url.Parse(p.Storage.PublicBaseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.ContainsAny(p.Storage.PublicBaseURL, "?#\\\r\n\t ") {
		return fmt.Errorf("public storage URL must be HTTPS without credentials, query or fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n > 65535 {
			return fmt.Errorf("invalid public URL port")
		}
	}
	ids, keys, keyIDs := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, i := range p.Identities {
		if ids[i.ID] || keys[i.PublicKey] || keyIDs[i.KeyID] {
			return fmt.Errorf("each identity must have a distinct ID, key ID and public key")
		}
		ids[i.ID] = true
		keys[i.PublicKey] = true
		keyIDs[i.KeyID] = true
		b, _ := hex.DecodeString(i.PublicKey)
		if Hash(b) != i.Fingerprint {
			return fmt.Errorf("identity %s fingerprint does not match its public key", i.ID)
		}
	}
	used, roles, counts, participants := map[string]bool{}, map[string]bool{}, map[string]int{}, map[string]bool{}
	allowedRoles := map[string]bool{"coordinator": true, "participant": true, "auditor": true, "release-signer": true}
	for _, r := range p.Roles {
		if !allowedRoles[r.Role] {
			return fmt.Errorf("unsupported setup role %q", r.Role)
		}
		if roles[r.ID] || used[r.IdentityID] || !ids[r.IdentityID] {
			return fmt.Errorf("each role must have a distinct ID and assigned identity")
		}
		roles[r.ID] = true
		used[r.IdentityID] = true
		counts[r.Role]++
		if r.Role == "participant" {
			participants[r.IdentityID] = true
		}
	}
	if len(used) != len(ids) {
		return fmt.Errorf("unassigned public identity")
	}
	if counts["coordinator"] != 1 || counts["release-signer"] != 1 {
		return fmt.Errorf("setup requires one coordinator and one release signer")
	}
	a := p.AssurancePolicy
	if a.PublicWitnessesPerPhase < 0 || a.PublicWitnessesPerPhase > 20 ||
		a.MirrorsPerAcceptedHead < 0 || a.MirrorsPerAcceptedHead > 20 ||
		a.PassingCeremonyAudits < 0 || a.PassingCeremonyAudits > 20 ||
		a.ExternalSecurityAuditSignoffs < 0 || a.ExternalSecurityAuditSignoffs > 20 {
		return fmt.Errorf("assurance requirements must be between 0 and 20")
	}
	if a.PassingCeremonyAudits > counts["auditor"] || (a.PassingCeremonyAudits == 0 && counts["auditor"] != 0) {
		return fmt.Errorf("auditor assignments must match the signed ceremony-audit requirement")
	}
	// Witness and mirror identities are assigned and enrolled after initialization.
	// The signed setup binds only their required counts, never mutable invitations.
	if a.ExternalSecurityAuditSignoffs != 0 {
		return fmt.Errorf("external security audit signoffs are not supported by this setup contract")
	}
	phases, scheduled := map[string]bool{}, map[string]bool{}
	for _, phase := range p.Phases {
		if phases[phase.ID] {
			return fmt.Errorf("duplicate phase")
		}
		phases[phase.ID] = true
		if phase.Minimum > len(phase.IdentityIDs) {
			return fmt.Errorf("phase minimum exceeds its participants")
		}
		if p.Mode == "production" && (len(phase.IdentityIDs) < 2 || phase.Minimum != len(phase.IdentityIDs)) {
			return fmt.Errorf("production requires at least two participants and all contributions per phase")
		}
		for _, id := range phase.IdentityIDs {
			if !participants[id] {
				return fmt.Errorf("phase member is not a participant")
			}
			scheduled[id] = true
		}
	}
	if len(scheduled) != len(participants) {
		return fmt.Errorf("each participant must be in at least one phase")
	}
	if s.Result != nil {
		h, e := s.InputDigest()
		if e != nil {
			return e
		}
		if s.Result.InputSHA256 != h {
			return fmt.Errorf("result belongs to a different setup plan")
		}
		found := map[string]bool{}
		for _, a := range s.Result.Artifacts {
			k := a.Kind + ":" + a.Platform
			if found[k] {
				return fmt.Errorf("duplicate artifact")
			}
			found[k] = true
			if (a.Kind == "tool-receipt") == (a.Platform == "none") {
				return fmt.Errorf("invalid artifact platform")
			}
			b, e := base64.StdEncoding.Strict().DecodeString(a.ContentB64)
			if e != nil || base64.StdEncoding.EncodeToString(b) != a.ContentB64 || len(b) != a.ByteLength || Hash(b) != a.SHA256 {
				return fmt.Errorf("artifact %s bytes do not match length or digest", a.Kind)
			}
			if a.Kind == "software-manifest" && a.SHA256 != p.SoftwareRelease.ManifestSHA256 {
				return fmt.Errorf("software manifest differs from selected release")
			}
		}
		for _, kind := range []string{"definition", "definition-signature", "coordinator-key", "software-manifest"} {
			if !found[kind+":none"] {
				return fmt.Errorf("missing %s artifact", kind)
			}
		}
	}
	return nil
}

// SamePlan compares the canonical public input, including website ID/revision.
func SamePlan(a, b Setup) bool {
	x, e := a.InputDigest()
	y, f := b.InputDigest()
	return e == nil && f == nil && bytes.Equal([]byte(x), []byte(y))
}
