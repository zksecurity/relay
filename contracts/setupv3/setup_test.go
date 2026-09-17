package setupv3

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSharedFixtures(t *testing.T) {
	raw, err := os.ReadFile("fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name   string
		JSON   string
		Valid  bool
		Input  string `json:"input_sha256"`
		SHA    string `json:"sha256"`
		Result string `json:"result_sha256"`
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			s, err := Parse([]byte(f.JSON))
			if !f.Valid {
				if err == nil {
					t.Fatal("invalid setup accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			input, err := s.InputDigest()
			if err != nil || input != f.Input {
				t.Fatalf("input digest %s: %v", input, err)
			}
			sha, err := s.Digest()
			if err != nil || sha != f.SHA {
				t.Fatalf("setup digest %s: %v", sha, err)
			}
			if s.Result != nil {
				result, err := s.Result.Digest()
				if err != nil || result != f.Result {
					t.Fatalf("result digest %s: %v", result, err)
				}
			}
		})
	}
}
func TestBoundsAndUTF8(t *testing.T) {
	for _, b := range [][]byte{[]byte(strings.Repeat(" ", MaxBytes+1)), {'"', 0xff, '"'}} {
		if _, err := Parse(b); err == nil {
			t.Fatal("invalid bytes accepted")
		}
	}
}

func fixtureSetup(t *testing.T) Setup {
	t.Helper()
	raw, err := os.ReadFile("fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		JSON string `json:"json"`
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil || len(fixtures) == 0 {
		t.Fatalf("load fixture: %v", err)
	}
	setup, err := Parse([]byte(fixtures[0].JSON))
	if err != nil {
		t.Fatal(err)
	}
	return *setup
}

func TestConfigurableBeaconLead(t *testing.T) {
	setup := fixtureSetup(t)
	setup.Plan.Mode = "production"
	setup.Plan.Circuit = "ownership-destination-v2"
	setup.Plan.BeaconPolicy = Beacon("production", 12)
	setup.Plan.Phases[0].IdentityIDs = append(setup.Plan.Phases[0].IdentityIDs, "participant-2")
	setup.Plan.Phases[1].IdentityIDs = append(setup.Plan.Phases[1].IdentityIDs, "participant-2")
	setup.Plan.Phases[0].Minimum, setup.Plan.Phases[1].Minimum = 2, 2
	second := Identity{ID: "participant-2", DisplayName: "Participant 2", KeyID: "key-4", PublicKey: strings.Repeat("04", 32), Fingerprint: "sha256:9f4fb68f3e1dac82202f9aa581ce0bbf1f765df0e9ac3c8c57e20f685abab8ed"}
	setup.Plan.Identities = append(setup.Plan.Identities, second)
	setup.Plan.Roles = append(setup.Plan.Roles, Role{ID: "00000000-0000-4000-8000-000000000004", Role: "participant", IdentityID: second.ID})
	if err := setup.Validate(); err != nil {
		t.Fatalf("short signed production lead rejected: %v", err)
	}
	setup.Plan.BeaconPolicy["minimum_witness_lead_seconds"] = float64(0)
	if err := setup.Validate(); err == nil {
		t.Fatal("zero beacon lead accepted")
	}
}

func TestOptionalAssuranceAndAssignments(t *testing.T) {
	setup := fixtureSetup(t)
	if err := setup.Validate(); err != nil {
		t.Fatalf("zero assurance rejected: %v", err)
	}
	setup.Plan.AssurancePolicy.PublicWitnessesPerPhase = 1
	setup.Plan.AssurancePolicy.MirrorsPerAcceptedHead = 1
	if err := setup.Validate(); err != nil {
		t.Fatalf("post-initialization observer requirements rejected: %v", err)
	}
	setup = fixtureSetup(t)
	setup.Plan.AssurancePolicy.PassingCeremonyAudits = 1
	if err := setup.Validate(); err == nil {
		t.Fatal("missing required auditor accepted")
	}
	setup = fixtureSetup(t)
	setup.Plan.Roles[2].Role = "witness"
	if err := setup.Validate(); err == nil {
		t.Fatal("observer identity accepted in authoritative setup plan")
	}
	setup = fixtureSetup(t)
	setup.Plan.AssurancePolicy.ExternalSecurityAuditSignoffs = 1
	if err := setup.Validate(); err == nil {
		t.Fatal("unsupported external security audit requirement accepted")
	}
}
