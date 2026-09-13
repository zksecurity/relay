package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Desired-contract regression: no Docker or child commands run.
func TestOnboardingModelContract(t *testing.T) {
	p := preparationFixture(t, "participant")
	prepareTestProfile(t, p, "keygen")
	prepareTestProfile(t, p, "decision-signer")
	p.d.Values["image"] = "sha256:" + strings.Repeat("b", 64)
	p.d.Values["binary"] = "/usr/local/bin/mpc-ceremony"
	prepareTestIdentity(t, p)
	reportTestPublicHandoff(t, p, "identity")
	// Deliberately synthetic local-presence state, NOT cryptographic evidence.
	for _, path := range []string{
		filepath.Join(p.d.Work, "ceremony/public/ceremony.json"),
		filepath.Join(p.d.Work, "ceremony/public/ceremony.sig"),
		filepath.Join(p.d.Trust, "coordinator-public-key.hex"),
		filepath.Join(p.d.Work, "enrollment.json"),
		filepath.Join(p.d.Work, "enrollment.sig"),
	} {
		if err := os.WriteFile(path, []byte("synthetic presence fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	prepareTestEnrollmentHandoff(t, p)
	reportTestPublicHandoff(t, p, "enrollment")
	storage := filepath.Join(p.d.Work, "ceremony/config/relay-storage.json")
	if _, err := os.Lstat(storage); !os.IsNotExist(err) {
		t.Fatalf("fixture must have no storage file: %v", err)
	}
	p.ui.input = bufio.NewReader(strings.NewReader("0\n"))
	if err := p.menu(); err != nil {
		t.Fatal(err)
	}
	output := p.ui.output.(*bytes.Buffer).String()
	t.Logf("Actual CLI menu (synthetic local files, no storage):\n%s", output)
	next := p.nextPreparationAction()
	if !strings.Contains(output, "NEXT SETUP STEP\n  "+next.label) {
		t.Fatal("adapter cannot locate the actual recommended step")
	}
	if next.choice != "3" || !strings.Contains(next.reason, "coordinator") || !strings.Contains(next.reason, "relay-storage.json") {
		t.Fatalf("MODEL_CONTRACT_STORAGE: recommended profile creation while relay-storage.json is absent; user needs coordinator handoff/import guidance first")
	}
}
