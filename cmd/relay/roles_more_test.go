package main

import (
	"strings"
	"testing"
)

func TestSyncNextStepMatchesRole(t *testing.T) {
	const (
		chain     = "/transcript/phase1/chain-0003.json"
		signature = "/transcript/phase1/chain-0003.sig"
		storedAt  = "2026-08-20T07:36:43Z"
	)

	mirror := syncNextStep("mirror sync", chain, signature, 3, storedAt)
	for _, want := range []string{"draft a receipt", "relay mirror receipt", chain, signature, storedAt} {
		if !strings.Contains(mirror, want) {
			t.Fatalf("mirror next step missing %q:\n%s", want, mirror)
		}
	}

	auditor := syncNextStep("auditor sync", chain, signature, 3, storedAt)
	if !strings.Contains(auditor, "ready for independent audit") {
		t.Fatalf("auditor next step is not audit-specific:\n%s", auditor)
	}
	if strings.Contains(auditor, "mirror") || strings.Contains(auditor, "receipt") {
		t.Fatalf("auditor next step suggests mirror behavior:\n%s", auditor)
	}
}
