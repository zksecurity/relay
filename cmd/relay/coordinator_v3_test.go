package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	setupv2 "github.com/zksecurity/relay/contracts/setupv2r2"
	setupv3 "github.com/zksecurity/relay/contracts/setupv3"
)

func TestCoordinatorCurrentCircuitModes(t *testing.T) {
	for _, tc := range []struct {
		mode, circuit string
		allowed       bool
	}{
		{"production", "ownership-destination-v3", true},
		{"rehearsal", "ownership-destination-v3", true},
		{"rehearsal", "rehearsal-tiny-v1", true},
		{"production", "rehearsal-tiny-v1", true},
		{"production", "rehearsal-k11-v1", true},
		{"rehearsal", "rehearsal-k11-v1", true},
		{"production", "ownership-destination-v2", false},
		{"rehearsal", "ownership-destination-v2", false},
	} {
		t.Run(tc.mode+"/"+tc.circuit, func(t *testing.T) {
			w := setupFixture(t)
			w.d.Mode, w.d.Circuit = tc.mode, tc.circuit
			if tc.mode == "production" {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(pub)
				second := setupIdentity{"participant2", "participant2", "participant2-key", hex.EncodeToString(pub), fmt.Sprintf("sha256:%x", hash)}
				w.d.Identities.Roster = append(w.d.Identities.Roster, setupParticipant{second})
				w.d.Policy.Phase1.Participants = append(w.d.Policy.Phase1.Participants, "participant2")
				w.d.Policy.Phase2.Participants = append(w.d.Policy.Phase2.Participants, "participant2")
				w.d.Policy.Phase1.Minimum, w.d.Policy.Phase2.Minimum = 2, 2
			}
			if err := w.d.validate(); (err == nil) != tc.allowed {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}

func TestCoordinatorIncompatibleInitializationPreservesDraft(t *testing.T) {
	for _, kind := range []string{"standalone-v2", "interrupted-v2", "tessera-v2", "tessera-v3-tiny"} {
		t.Run(kind, func(t *testing.T) {
			w := setupFixture(t)
			switch kind {
			case "standalone-v2":
				w.d.Circuit = "ownership-destination-v2"
			case "interrupted-v2":
				w.d.Circuit = "ownership-destination-v2"
				w.d.Status = "initialization-attempted"
			case "tessera-v2":
				w.d.Circuit = "ownership-destination-v2"
				w.d.TesseraSetup = &setupv2.Setup{}
			case "tessera-v3-tiny":
				w.d.TesseraSetupV3 = &setupv3.Setup{}
			}
			if err := w.save(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(w.draftPath)
			if err != nil {
				t.Fatal(err)
			}
			stateBefore, _ := json.Marshal(w.d)
			w.run = func([]string) error { t.Fatal("ran initialization"); return nil }
			w.prepareBinaries = func() error { t.Fatal("prepared binaries"); return nil }
			err = w.initialize()
			if err == nil || !strings.Contains(err.Error(), "release") {
				t.Fatalf("missing actionable compatibility error: %v", err)
			}
			after, err := os.ReadFile(w.draftPath)
			if err != nil {
				t.Fatal(err)
			}
			stateAfter, _ := json.Marshal(w.d)
			if !bytes.Equal(before, after) || !bytes.Equal(stateBefore, stateAfter) {
				t.Fatal("incompatible initialization modified draft")
			}
			if _, err := os.Stat(filepath.Join(w.d.Work, "ceremony")); !os.IsNotExist(err) {
				t.Fatal("created ceremony output", err)
			}
		})
	}
}
