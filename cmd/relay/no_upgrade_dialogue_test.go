package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Run the same file on main and the candidate. This compares real menu functions
// and persisted fixture state without installing an upgrade or contacting storage.
// Child calls are captured, not executed; Docker execution has separate coverage.
// The default digest baseline was captured from main at 5f1d3b10df50b26176f4a82565201c2e52c310ce.
// Only fixture root paths and synthetic hexadecimal keys are normalized.
func TestNeverUpgradedDialogueComparison(t *testing.T) {
	snapshots := map[string]string{}
	normalize := func(s, root string) string {
		s = strings.ReplaceAll(s, root, "<ROLE>")
		return regexp.MustCompile("[0-9a-f]{64,128}").ReplaceAllString(s, "<KEY>")
	}
	for _, role := range []string{"participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		t.Run(role, func(t *testing.T) {
			p := preparationFixture(t, role)
			root := filepath.Dir(p.d.Work)
			for _, stage := range []string{"new", "prepared"} {
				if stage == "prepared" {
					prepareTestProfile(t, p, "keygen")
					prepareTestProfile(t, p, "decision-signer")
					prepareTestProfile(t, p, role)
					if role != "upload-station" {
						prepareTestIdentity(t, p)
					}
					if role == "participant" {
						prepareParticipantRoleConfig(t, p, "sha256:"+strings.Repeat("b", 64), "linux/arm64")
					}
				}
				p.ui.input = bufio.NewReader(strings.NewReader("6\n0\n"))
				p.ui.output = new(bytes.Buffer)
				if err := p.menu(); err != nil {
					t.Fatal(err)
				}
				output := p.ui.output.(*bytes.Buffer).String()
				if strings.Contains(output, "Stopped:") {
					t.Fatal(output)
				}
				snapshots[role+"/"+stage+"/menu"] = normalize(output, root)
				raw, err := os.ReadFile(p.path)
				if err != nil {
					t.Fatal(err)
				}
				snapshots[role+"/"+stage+"/draft"] = normalize(string(raw), root)
				var reopened rolePreparation
				if err := setupReadJSON(p.path, &reopened); err != nil {
					t.Fatal(err)
				}
				p.d = reopened
				if stage == "prepared" {
					p.ui.output = new(bytes.Buffer)
					if role != "upload-station" {
						if err := p.identity(); err != nil {
							t.Fatal(err)
						}
					}
					snapshots[role+"/identity-review"] = normalize(p.ui.output.(*bytes.Buffer).String(), root)
					executionRole := role
					if role == "participant" {
						executionRole = "decision-signer"
					}
					profile, err := p.profile(executionRole)
					if err != nil {
						t.Fatal(err)
					}
					raw, _ := json.Marshal(profile)
					snapshots[role+"/profile"] = normalize(string(raw), root)
					p.run = func(args []string) error {
						snapshots[role+"/child"] = normalize(strings.Join(args, "\n"), root)
						return nil
					}
					if err := p.open(executionRole, "read-only", []string{"mpc-ceremony", "inspect", "definition"}); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
	t.Run("coordinator", func(t *testing.T) {
		w := setupFixture(t)
		root := filepath.Dir(w.d.Work)
		for _, stage := range []string{"draft", "definition-verified"} {
			w.d.Status = stage
			w.input = bufio.NewReader(strings.NewReader("0\n"))
			w.output = new(bytes.Buffer)
			if err := w.menu(); err != nil {
				t.Fatal(err)
			}
			snapshots["coordinator/"+stage+"/menu"] = normalize(w.output.(*bytes.Buffer).String(), root)
			raw, err := os.ReadFile(w.draftPath)
			if err != nil {
				t.Fatal(err)
			}
			snapshots["coordinator/"+stage+"/draft"] = normalize(string(raw), root)
			if err := setupReadJSON(w.draftPath, &w.d); err != nil {
				t.Fatal(err)
			}
		}
	})
	raw, err := json.MarshalIndent(snapshots, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if output := os.Getenv("RELAY_NO_UPGRADE_SNAPSHOT"); output != "" {
		if err := os.WriteFile(output, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	expected := os.Getenv("RELAY_NO_UPGRADE_EXPECTED")
	hashes := expected == ""
	if hashes {
		expected = "testdata/no-upgrade-main-sha256.json"
	}
	{
		previous, err := os.ReadFile(expected)
		if err != nil {
			t.Fatal(err)
		}
		var want map[string]string
		if err := json.Unmarshal(previous, &want); err != nil {
			t.Fatal(err)
		}
		if len(want) != len(snapshots) {
			t.Fatalf("snapshot count %d != %d", len(snapshots), len(want))
		}
		for k, v := range want {
			got := snapshots[k]
			if hashes {
				got = fmt.Sprintf("%x", sha256.Sum256([]byte(got)))
			}
			if got != v {
				t.Errorf("changed %s\nMAIN:\n%s\nCANDIDATE:\n%s", k, v, snapshots[k])
			}
		}
	}
}
