package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/verification"
)

func verificationFixture(t *testing.T, decision ...bool) string {
	t.Helper()
	m := verification.Manifest{Schema: verification.Schema, CeremonyID: "sha256:" + strings.Repeat("a", 64), ReleaseKeyID: "release-key", Inputs: map[string]string{}}
	data := map[string][]byte{}
	for _, key := range verification.RequiredInputs {
		p := "data/" + key
		m.Inputs[key] = p
		if key == "transcript-root" || key == "keys-dir" {
			p += "/file"
		}
		b := []byte(key)
		data[p] = b
		h := sha256.Sum256(b)
		hash := hex.EncodeToString(h[:])
		m.Files = append(m.Files, verification.File{Path: p, Size: int64(len(b)), SHA256: hash})
		if key == "ceremony" {
			m.DefinitionSHA256 = hash
		}
	}
	if len(decision) > 0 && decision[0] {
		m.Decision = &verification.Decision{Record: "decision.json", Signatures: []string{"decision.sig"}, EvidenceRoot: "evidence"}
		for _, name := range []string{"decision.json", "decision.sig", "evidence/file"} {
			b := []byte("fixture")
			data[name] = b
			hash := sha256.Sum256(b)
			m.Files = append(m.Files, verification.File{Path: name, Size: int64(len(b)), SHA256: hex.EncodeToString(hash[:])})
		}
	}
	p := filepath.Join(t.TempDir(), "archive.zip")
	f, _ := os.Create(p)
	z := zip.NewWriter(f)
	w, _ := z.Create("verification.json")
	raw, _ := json.Marshal(m)
	w.Write(raw)
	for p, b := range data {
		w, _ := z.Create(p)
		w.Write(b)
	}
	z.Close()
	f.Close()
	return p
}
func TestPublicVerificationStages(t *testing.T) {
	for _, tc := range []struct {
		name, mode, fail string
		want             bool
		last             string
	}{{"rehearsal", "rehearsal", "", true, "not-applicable"}, {"production-needs-approval", "production", "", false, "missing-evidence"}, {"replay-fails", "rehearsal", "replay", false, "not-run"}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := []string{}
			runner := func(args ...string) ([]byte, error) {
				command := args[0]
				if command == "inspect" || command == "release" || command == "decision" {
					command += " " + args[1]
				}
				calls = append(calls, command)
				if command == tc.fail {
					return nil, errors.New("verification failed")
				}
				r := map[string]any{"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": command, "release_manifest_sha256": "sha256:" + strings.Repeat("b", 64), "ceremony_id": "sha256:" + strings.Repeat("a", 64)}
				if command == "inspect definition" {
					r["definition_inspection"] = map[string]any{"schema": "proof-tool-mpc-definition-inspection-v1", "ceremony_id": "sha256:" + strings.Repeat("a", 64), "mode": tc.mode, "r1cs": map[string]any{"name": "circuit.r1cs", "digest": map[string]any{"sha256": strings.Repeat("a", 64), "blake2b256": strings.Repeat("b", 64), "size": 1}}, "phase1_participants": []string{"a"}, "phase2_participants": []string{"a"}}
				}
				return json.Marshal(r)
			}
			r, e := verifyCeremonyArchive(verificationFixture(t), 1<<20, runner)
			if r.Passed != tc.want || (e == nil) != tc.want {
				t.Fatalf("report=%+v error=%v calls=%v", r, e, calls)
			}
			if r.Checks[4].Status != tc.last {
				t.Fatalf("approval status %+v", r.Checks[4])
			}
			if len(calls) != 3 || calls[2] != "replay" {
				t.Fatalf("missing mandatory replay: %v", calls)
			}
		})
	}
}

func TestProductionApprovalMustBeGOAndMatchVerifiedRelease(t *testing.T) {
	for _, tc := range []struct {
		name, decision, hash string
		pass                 bool
	}{{"go", "GO", strings.Repeat("b", 64), true}, {"no-go", "NO-GO", strings.Repeat("b", 64), false}, {"other-release", "GO", strings.Repeat("c", 64), false}} {
		t.Run(tc.name, func(t *testing.T) {
			runner := func(args ...string) ([]byte, error) {
				command := args[0]
				if command != "replay" {
					command += " " + args[1]
				}
				r := map[string]any{"schema": "proof-tool-mpc-command-result-v1", "ok": true, "command": command, "ceremony_id": "sha256:" + strings.Repeat("a", 64), "release_manifest_sha256": "sha256:" + strings.Repeat("b", 64)}
				if command == "inspect definition" {
					r["definition_inspection"] = map[string]any{"schema": "proof-tool-mpc-definition-inspection-v1", "ceremony_id": "sha256:" + strings.Repeat("a", 64), "mode": "production", "phase1_participants": []string{"a"}, "phase2_participants": []string{"a"}, "r1cs": map[string]any{"name": "circuit.r1cs", "digest": map[string]any{"sha256": strings.Repeat("a", 64), "blake2b256": strings.Repeat("b", 64), "size": 1}}}
				}
				if command == "decision verify" {
					r["decision"] = tc.decision
					r["release_manifest_sha256"] = "sha256:" + tc.hash
				}
				return json.Marshal(r)
			}
			report, err := verifyCeremonyArchive(verificationFixture(t, true), 1<<20, runner)
			if report.Passed != tc.pass || (err == nil) != tc.pass {
				t.Fatalf("%+v: %v", report, err)
			}
		})
	}
}
func TestPackSelectsOnlyExplicitPublicFiles(t *testing.T) {
	extracted, m, err := verification.Extract(verificationFixture(t), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(extracted)
	if err := os.WriteFile(filepath.Join(extracted, "private-key-not-for-export"), []byte("test-only-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "public.zip")
	if err := packCeremony(extracted, archive, m); err != nil {
		t.Fatal(err)
	}
	root, _, err := verification.Extract(archive, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if _, err := os.Stat(filepath.Join(root, "private-key-not-for-export")); !os.IsNotExist(err) {
		t.Fatal("unlisted private file exported")
	}
	if err := packCeremony(extracted, archive, m); err == nil {
		t.Fatal("existing archive overwritten")
	}
}
