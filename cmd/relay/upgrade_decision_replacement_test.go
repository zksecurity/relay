package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUpgradeSyntheticUnsignedDecisionAndRetiredHistory(t *testing.T) {
	for _, retired := range []bool{false, true} {
		name := "active"
		if retired {
			name = "retired"
		}
		t.Run(name, func(t *testing.T) {
			s, declaration := testUpgradeV2(t, "coordinator")
			m := replacementFixtureAt(t, s.Profile.Work)
			if retired {
				for _, item := range m.Items {
					from := filepath.Join(s.Profile.Work, filepath.FromSlash(item.Source))
					to := decisionReplacementRetiredPath(s.Profile.Work, m, item.Source)
					if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(from, to); err != nil {
						t.Fatal(err)
					}
				}
				if err := writeJSONNoReplace(filepath.Join(decisionReplacementRoot(s.Profile.Work), m.Generation, "committed"), map[string]string{"decision_sha256": m.OldDecisionSHA256}, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				// An older release has the active guided files but no replacement
				// intent yet. The new upgrade must admit those fixed paths.
				if err := os.RemoveAll(decisionReplacementRoot(s.Profile.Work)); err != nil {
					t.Fatal(err)
				}
			}
			paths := decisionReplacementPaths(s.Profile.Work)
			if retired {
				for i, item := range m.Items {
					paths[i] = decisionReplacementRetiredPath(s.Profile.Work, m, item.Source)
				}
			}
			before := make([][]decisionReplacementFile, len(paths))
			for i, path := range paths {
				files, _, err := decisionReplacementTree(path)
				if err != nil {
					t.Fatal(err)
				}
				before[i] = files
			}
			inv, err := upgradeV2Inventory(s.Profile, declaration)
			if err != nil {
				t.Fatalf("synthetic retained-state upgrade inventory: %v", err)
			}
			s.Kinds, s.InventorySHA256 = inv.Kinds, inv.digest()
			if err := upgradeV2Activate(s, ""); err != nil {
				t.Fatalf("synthetic upgrade activation: %v", err)
			}
			for i, path := range paths {
				after, _, err := decisionReplacementTree(path)
				if err != nil {
					t.Fatal(err)
				}
				if !decisionReplacementSameFiles(before[i], after) {
					t.Fatal("upgrade changed retained decision bytes")
				}
			}
			if retired {
				state, err := decisionReplacementReadState(s.Profile.Work)
				if err != nil || !state.Awaiting {
					t.Fatalf("retired state changed during upgrade: %+v, %v", state, err)
				}
			}
		})
	}
}
