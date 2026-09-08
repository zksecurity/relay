package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFlowIdentityChoicesUsePublicDisplayNames(t *testing.T) {
	p := preparationFixture(t, "auditor")
	prepareTestIdentity(t, p)
	f := flowFixture(t)
	f.state.Role = "auditor"
	f.state.Profile.Keys = p.d.Keys
	choices, err := f.identityChoices(flowTask{}, ft("auditor-id", "Auditor", ""))
	if err != nil || len(choices) != 1 || choices[0].value != "my-id" || choices[0].label != "My name (my-id)" {
		t.Fatalf("%v %v", choices, err)
	}
	// The helper reads only the public identity, never the private seed.
	if _, err := os.Stat(filepath.Join(p.d.Keys, "signing.hex")); !os.IsNotExist(err) {
		t.Fatal("test unexpectedly has a signing key")
	}
	f.state.Profile.Keys = ""
	choices, err = f.identityChoices(flowTask{}, ft("auditor-id", "Auditor", ""))
	if err != nil || len(choices) != 0 {
		t.Fatal("invented an identity without a local public file")
	}
}
