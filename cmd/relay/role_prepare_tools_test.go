package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolPreparationFailureSurvivesReopenAndRetry(t *testing.T) {
	for _, failure := range []string{"keygen", "decision-signer", "release-signer"} {
		t.Run(failure, func(t *testing.T) {
			p := preparationFixture(t, "release-signer")
			prepareTestIdentity(t, p)
			identityPath := filepath.Join(p.d.Keys, "identity.json")
			identity, _ := os.ReadFile(identityPath)
			receiptPath := filepath.Join(p.d.Trust, "tool-identity-receipt.env")
			receipt := []byte("retained receipt must not be replaced")
			if err := os.WriteFile(receiptPath, receipt, 0600); err != nil {
				t.Fatal(err)
			}
			p.run = func(args []string) error {
				role := ""
				for i, arg := range args {
					if arg == "--role" {
						role = args[i+1]
					}
				}
				if role == failure {
					return errors.New("preparation interrupted")
				}
				prepareTestProfile(t, p, role)
				return nil
			}
			if err := p.images(); err == nil {
				t.Fatal("expected preparation failure")
			}
			var reopened rolePreparation
			if err := setupReadJSON(p.path, &reopened); err != nil {
				t.Fatal(err)
			}
			p.d = reopened
			if got := p.nextPreparationAction(); got.choice != "1" || !strings.Contains(got.reason, "did not finish") {
				t.Fatalf("advanced past interrupted preparation: %+v", got)
			}
			p.run = func(args []string) error {
				for i, arg := range args {
					if arg == "--role" {
						prepareTestProfile(t, p, args[i+1])
						return nil
					}
				}
				t.Fatal("missing role")
				return nil
			}
			if err := p.images(); err != nil {
				t.Fatal(err)
			}
			if err := setupReadJSON(p.path, &reopened); err != nil {
				t.Fatal(err)
			}
			if reopened.Values[toolPreparationIncomplete] != "" {
				t.Fatal("successful retry remained incomplete")
			}
			if got := p.nextPreparationAction(); got.choice != "9" {
				t.Fatalf("successful signer setup did not advance: %+v", got)
			}
			actual, _ := os.ReadFile(identityPath)
			if !bytes.Equal(actual, identity) {
				t.Fatal("identity changed")
			}
			actual, _ = os.ReadFile(receiptPath)
			if !bytes.Equal(actual, receipt) {
				t.Fatal("retained receipt changed")
			}
		})
	}
}

func TestToolPreparationSaveFailuresDoNotAdvance(t *testing.T) {
	t.Run("initial save", func(t *testing.T) {
		p := preparationFixture(t, "participant")
		p.path = p.d.Work // A directory cannot be replaced by the draft file.
		p.run = func([]string) error { t.Fatal("setup ran before initial save"); return nil }
		if err := p.images(); err == nil {
			t.Fatal("expected save failure")
		}
	})
	t.Run("final save", func(t *testing.T) {
		p := preparationFixture(t, "release-signer")
		originalPath := p.path
		prepareTestProfile(t, p, "keygen")
		prepareTestProfile(t, p, "decision-signer")
		p.run = func([]string) error { p.path = p.d.Work; return nil }
		if err := p.images(); err == nil {
			t.Fatal("expected completion save failure")
		}
		if got := p.nextPreparationAction(); got.choice != "1" {
			t.Fatalf("advanced despite failed completion save: %+v", got)
		}
		var saved rolePreparation
		if err := setupReadJSON(originalPath, &saved); err != nil {
			t.Fatal(err)
		}
		if saved.Values[toolPreparationIncomplete] == "" {
			t.Fatal("durable incomplete marker lost")
		}
	})
}

func TestIncompleteParticipantToolsTakePrecedenceOverRetainedProfiles(t *testing.T) {
	p := preparationFixture(t, "participant")
	prepareTestProfile(t, p, "keygen")
	prepareTestProfile(t, p, "decision-signer")
	prepareTestIdentity(t, p)
	p.d.Values["image"] = "sha256:" + strings.Repeat("b", 64)
	p.d.Values["binary"] = "/retained/approved-tools/mpc-ceremony"
	p.d.Values[toolPreparationIncomplete] = "interrupted"
	if err := p.save(); err != nil {
		t.Fatal(err)
	}
	var reopened rolePreparation
	if err := setupReadJSON(p.path, &reopened); err != nil {
		t.Fatal(err)
	}
	p.d = reopened
	if got := p.nextPreparationAction(); got.choice != "1" {
		t.Fatalf("recommended identity handoff after failed tools: %+v", got)
	}
}
