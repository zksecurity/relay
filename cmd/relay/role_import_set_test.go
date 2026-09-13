package main

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func importSetFixture(t *testing.T, role string) (*rolePreparer, string, [][]byte) {
	t.Helper()
	p := preparationFixture(t, role)
	profile := "decision-signer"
	if role == "upload-station" {
		profile = role
	}
	prepareTestProfile(t, p, profile)
	source := filepath.Join(p.d.Work, "received")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{[]byte(`{"test":"definition"}`), []byte(`{"test":"signature"}`), []byte(strings.Repeat("ab", 32))}
	for n, file := range ceremonyImportFiles {
		if err := os.WriteFile(filepath.Join(source, file.name), inputs[n], 0600); err != nil {
			t.Fatal(err)
		}
	}
	p.ui.input = bufio.NewReader(strings.NewReader("\n" + source + "\nVERIFIED\n"))
	return p, source, inputs
}

// These tests exercise orchestration, not proof-tool's cryptographic verifier.
func TestImportCeremonySetRetryAndRoles(t *testing.T) {
	for _, role := range []string{"participant", "auditor", "witness", "mirror", "release-signer", "upload-station"} {
		t.Run(role, func(t *testing.T) {
			p, source, inputs := importSetFixture(t, role)
			actions := map[string]bool{}
			p.run = func(args []string) error {
				if commandValue(args, "role") == "decision-signer" && role == "upload-station" {
					t.Fatal("uploader used signer")
				}
				if !strings.Contains(strings.Join(args, " "), "mpc-ceremony inspect definition") {
					t.Fatal(args)
				}
				action := commandValue(args, "action")
				if actions[action] {
					t.Fatal("reused immutable action")
				}
				actions[action] = true
				for n, flag := range []string{"ceremony", "ceremony-signature", "coordinator-public-key-file"} {
					path := filepath.Join(p.d.Work, strings.TrimPrefix(commandValue(args, flag), "/work/"))
					raw, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(raw, inputs[n]) {
						t.Fatal(path, err)
					}
				}
				return nil
			}
			for i := 0; i < 2; i++ {
				p.ui.input = bufio.NewReader(strings.NewReader("\n" + source + "\nVERIFIED\n"))
				if err := p.importFile(); err != nil {
					t.Fatal(err)
				}
			}
			for n, file := range ceremonyImportFiles {
				raw, err := os.ReadFile(preparationDestination(p.d, file.kind))
				if err != nil || !bytes.Equal(raw, inputs[n]) {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestImportCeremonySetRejectsBeforePublishing(t *testing.T) {
	for _, scenario := range []string{"missing", "conflict", "cancel", "verification", "tampered-stage", "destination-race", "symlink"} {
		t.Run(scenario, func(t *testing.T) {
			p, source, _ := importSetFixture(t, "participant")
			called := false
			p.run = func(args []string) error {
				called = true
				switch scenario {
				case "verification":
					return errors.New("signature rejected")
				case "tampered-stage":
					return os.WriteFile(filepath.Join(p.d.Work, strings.TrimPrefix(commandValue(args, "ceremony"), "/work/")), []byte("changed"), 0600)
				case "destination-race":
					return os.WriteFile(preparationDestination(p.d, "signature"), []byte("other"), 0600)
				}
				return nil
			}
			switch scenario {
			case "missing":
				if err := os.Remove(filepath.Join(source, "ceremony.sig")); err != nil {
					t.Fatal(err)
				}
			case "conflict":
				if err := os.WriteFile(preparationDestination(p.d, "signature"), []byte("other"), 0600); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				p.ui.input = bufio.NewReader(strings.NewReader("8\n" + source + "\nNO\n"))
			case "symlink":
				path := filepath.Join(source, "ceremony.sig")
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(source, "ceremony.json"), path); err != nil {
					t.Fatal(err)
				}
			}
			if err := p.importFile(); err == nil {
				t.Fatal("accepted invalid import")
			}
			if _, err := os.Stat(preparationDestination(p.d, "definition")); !os.IsNotExist(err) {
				t.Fatal("definition published", err)
			}
			if called && (scenario == "missing" || scenario == "conflict" || scenario == "cancel" || scenario == "symlink") {
				t.Fatal("unexpected inspection")
			}
		})
	}
}

func TestImportCeremonySetMatchingPartialRetry(t *testing.T) {
	for prefix := 1; prefix <= 3; prefix++ {
		p, _, inputs := importSetFixture(t, "participant")
		for n := 0; n < prefix; n++ {
			if err := publishPublicInput(preparationDestination(p.d, ceremonyImportFiles[n].kind), inputs[n]); err != nil {
				t.Fatal(err)
			}
		}
		p.run = func([]string) error { return nil }
		if err := p.importFile(); err != nil {
			t.Fatal(prefix, err)
		}
	}
}
