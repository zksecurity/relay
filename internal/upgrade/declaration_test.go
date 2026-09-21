package upgrade

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixture() Declaration {
	return Declaration{Schema: Schema, SourceRelease: strings.Repeat("a", 40), TargetRelease: strings.Repeat("b", 40), Role: "coordinator", Platform: "linux/arm64", ProfileSchema: "relay-guided-role-v1", WorkflowSchema: "relay-workflow-v4-state-v1", SourceOnlineImage: "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + strings.Repeat("c", 64), TargetOnlineImage: "ghcr.io/zksecurity/relay/relay-role-online@sha256:" + strings.Repeat("d", 64), ProofToolSHA256: "sha256:" + strings.Repeat("e", 64), OldVersionReentrySafe: true}
}

func TestDeclarationRejectsSubstitution(t *testing.T) {
	d := fixture()
	source := Installation{d.SourceRelease, d.SourceOnlineImage, d.ProofToolSHA256}
	target := Installation{d.TargetRelease, d.TargetOnlineImage, d.ProofToolSHA256}
	if err := d.Match(source, target); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Installation){
		func(x *Installation) { x.Release = strings.Repeat("f", 40) },
		func(x *Installation) { x.OnlineImage = d.SourceOnlineImage },
		func(x *Installation) { x.ProofToolSHA256 = "sha256:" + strings.Repeat("f", 64) },
	} {
		bad := target
		mutate(&bad)
		if d.Match(source, bad) == nil {
			t.Fatal("accepted substituted target")
		}
	}
	d.OldVersionReentrySafe = false
	if d.Match(source, target) == nil {
		t.Fatal("accepted unsafe downgrade")
	}
}

func TestDecodeRejectsAmbiguousDeclaration(t *testing.T) {
	raw, _ := json.Marshal(fixture())
	if _, err := Decode(raw); err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		append(append([]byte{}, raw...), raw...),
		[]byte(strings.Replace(string(raw), `"role":"coordinator"`, `"role":"participant","role":"coordinator"`, 1)),
		[]byte(strings.Replace(string(raw), `"role":"coordinator"`, `"extra":true,"role":"coordinator"`, 1)),
		[]byte(strings.Repeat(" ", MaximumBytes+1)),
	}
	for _, bad := range cases {
		if _, err := Decode(bad); err == nil {
			t.Fatal("accepted ambiguous declaration")
		}
	}
}
