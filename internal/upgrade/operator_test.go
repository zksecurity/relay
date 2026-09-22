package upgrade

import (
	"encoding/json"
	"testing"
)

func TestOperatorTransitionDoesNotClaimQualification(t *testing.T) {
	d := fixtureV2()
	d.Schema = OperatorTransitionSchema
	d.QualificationSHA256 = ""
	d.SafePredecessors = nil
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeV2(raw); err != nil {
		t.Fatal(err)
	}
	if err := d.Cover([]string{d.SourceApp}, []string{"inspect", "checkpoint"}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyQualification(nil, d); err == nil {
		t.Fatal("operator choice treated as evidence")
	}
	for name, change := range map[string]func(*DeclarationV2){
		"invented report":  func(d *DeclarationV2) { d.QualificationSHA256 = fixtureV2().QualificationSHA256 },
		"invented reentry": func(d *DeclarationV2) { d.SafePredecessors = []string{d.SourceApp} },
		"mutable runtime":  func(d *DeclarationV2) { d.OnlineImage = "latest" },
		"unknown storage":  func(d *DeclarationV2) { d.StorageLayout = "unknown" },
		"missing proof":    func(d *DeclarationV2) { d.ProofToolSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := d
			change(&bad)
			if bad.Validate() == nil {
				t.Fatal("accepted invalid transition")
			}
		})
	}
	if err := d.Cover(nil, []string{"contribute"}); err == nil {
		t.Fatal("accepted unsupported retained operation")
	}
}
