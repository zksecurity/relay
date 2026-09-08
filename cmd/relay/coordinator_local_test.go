//go:build relaylocal

package main

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalCoordinatorBoundaries(t *testing.T) {
	if coordinatorLocalRunner == nil {
		t.Fatal("local entry point not registered")
	}
	allowed := []string{"mpc-ceremony", "init", "--mode", "rehearsal", "--key-version", "rehearsal-tiny-v1"}
	if !localTestCommandAllowed("coordinator", allowed, false) {
		t.Fatal("tiny init rejected")
	}
	for _, command := range [][]string{
		{"relay", "coordinator", "configure-storage"},
		{"mpc-ceremony", "init", "--mode", "production", "--key-version", "ownership-destination-v2"},
		{"mpc-ceremony", "init", "--mode", "rehearsal", "--key-version", "ownership-destination-v2"},
		append(append([]string(nil), allowed...), "--allowed-binary", "extra"),
		{"mpc-ceremony", "phase1", "contribute"},
	} {
		if localTestCommandAllowed("coordinator", command, false) {
			t.Fatal("unsafe local command accepted", command)
		}
	}
	if localTestCommandAllowed("coordinator", allowed, true) {
		t.Fatal("local credentials accepted")
	}
	w := setupFixture(t)
	w.localAction = func(string, string, []string, bool) error { t.Fatal("local action executed"); return nil }
	w.input = bufio.NewReader(strings.NewReader("2\n1\n"))
	if err := w.basics(); err == nil {
		t.Fatal("production mode accepted")
	}
	if err := w.configureStorage(); err == nil {
		t.Fatal("cloud action accepted")
	}
	w.d.Mode = "production"
	w.d.Circuit = "ownership-destination-v2"
	if err := w.initialize(); err == nil {
		t.Fatal("production init accepted")
	}
}

func TestClearLegacyMocksPreservesRealImports(t *testing.T) {
	w := setupFixture(t)
	d := w.d
	d.Release = "LOCAL-REHEARSAL"
	for _, i := range []*setupIdentity{&d.Identities.ReleaseSigner, &d.Identities.Auditors[0], &d.Identities.Roster[0].Identity} {
		i.DisplayName = "MOCK " + i.ID
	}
	coordinator := d.Identities.Coordinator
	realAuditor := d.Identities.Auditors[1]
	n, err := clearLocalMockAssignments(&d)
	if err != nil || n != 3 {
		t.Fatal(n, err)
	}
	if d.Identities.Coordinator != coordinator || len(d.Identities.Auditors) != 1 || d.Identities.Auditors[0] != realAuditor {
		t.Fatal("real identities were changed")
	}
	if d.Identities.ReleaseSigner.ID != "" || len(d.Identities.Roster) != 0 || len(d.Policy.Phase1.Participants) != 0 {
		t.Fatal("mock assignments/orders retained")
	}
	d.Status = "initialization-attempted"
	if _, err := clearLocalMockAssignments(&d); err == nil {
		t.Fatal("changed frozen draft")
	}
	d.Status = "draft"
	d.Release = w.d.Release
	if _, err := clearLocalMockAssignments(&d); err == nil {
		t.Fatal("changed nonlocal draft")
	}
}

func TestSeparateLocalIdentityGenerationDoesNotImport(t *testing.T) {
	w := setupFixture(t)
	root := t.TempDir()
	var out bytes.Buffer
	var keys string
	calls := 0
	run := func(args []string) error {
		calls++
		if args[1] == "setup" {
			identity := w.d.Identities.Roster[0].Identity
			for n, a := range args {
				switch a {
				case "--work":
					keys = args[n+1]
				case "--identity-id":
					identity.ID = args[n+1]
				case "--display-name":
					identity.DisplayName = args[n+1]
				}
			}
			if !strings.HasPrefix(keys, filepath.Join(root, "test-roles")+string(filepath.Separator)) {
				t.Fatal("keys not isolated")
			}
			return setupWriteNew(filepath.Join(keys, "identity.json"), identity)
		}
		if args[1] != "open" {
			t.Fatal(args)
		}
		return nil
	}
	if err := generateLocalRoleIdentity(root, "sha256:"+strings.Repeat("a", 64), run, strings.NewReader("1\nAlice\nGENERATE\n"), &out); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !strings.Contains(out.String(), filepath.Join(keys, "identity.json")) {
		t.Fatal("missing generation or public handoff")
	}
	if w.d.Identities.Roster[0].Identity.DisplayName == "Alice" {
		t.Fatal("automatically imported generated identity")
	}
}
