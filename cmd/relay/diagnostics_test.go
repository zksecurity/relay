package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func diagnosticTestContext(t *testing.T) diagnosticContext {
	t.Helper()
	return diagnosticContext{Work: t.TempDir(), Role: "participant", Release: strings.Repeat("a", 40), Stage: "setup", Action: "2"}
}

func readReport(t *testing.T, path string) []byte {
	t.Helper()
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 2 {
		t.Fatalf("unexpected files: %d", len(z.File))
	}
	var all []byte
	for _, f := range z.File {
		if f.Name != "README.txt" && f.Name != "report.json" {
			t.Fatal(f.Name)
		}
		if f.Mode().Perm() != 0600 {
			t.Fatal("archive member permissions")
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, raw...)
	}
	return all
}

func TestDiagnosticsPrivacyAndExport(t *testing.T) {
	c := diagnosticTestContext(t)
	secret := "SENTINEL_SECRET_NEVER_EXPORT"
	for _, name := range []string{"signing.hex", "grant.json", "profile.json", "transcript.log"} {
		if err := os.WriteFile(filepath.Join(c.Work, name), []byte(secret), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("RELAY_TEST_SECRET", secret)
	err := appendDiagnostic(c, "failed", fmt.Errorf("child stderr: %s /Users/private-person/key.hex https://store.example/?token=%s", secret, secret))
	if err != nil {
		t.Fatal(err)
	}
	root, err := diagnosticRoot(c.Work, false)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "events.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("private-person")) {
		t.Fatal("sensitive message persisted")
	}
	// Exporter must not run daemon checks or inherit raw output into the report.
	t.Setenv("PATH", t.TempDir())
	out := filepath.Join(t.TempDir(), "report.zip")
	id, err := exportDiagnostics(c.Work, out)
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 24 {
		t.Fatal("missing report ID")
	}
	report := readReport(t, out)
	for _, forbidden := range []string{secret, "private-person", c.Work, "store.example", "key.hex"} {
		if bytes.Contains(report, []byte(forbidden)) {
			t.Fatalf("leaked %s", forbidden)
		}
	}
	for _, want := range []string{"operation-failed", "participant", "unavailable", id} {
		if !bytes.Contains(report, []byte(want)) {
			t.Fatalf("missing %s", want)
		}
	}
	info, _ := os.Stat(out)
	if info.Mode().Perm() != 0600 {
		t.Fatal("report permissions")
	}
	before, _ := os.ReadFile(out)
	if _, err := exportDiagnostics(c.Work, out); err == nil {
		t.Fatal("overwrote report")
	}
	after, _ := os.ReadFile(out)
	if !bytes.Equal(before, after) {
		t.Fatal("existing report changed")
	}
}

func TestDiagnosticsBoundedHistoryAndIsolation(t *testing.T) {
	c := diagnosticTestContext(t)
	for i := 0; i < diagnosticLimit+3; i++ {
		if err := appendDiagnostic(c, "failed", &os.PathError{Op: "open", Path: "secret", Err: os.ErrNotExist}); err != nil {
			t.Fatal(err)
		}
	}
	root, _ := diagnosticRoot(c.Work, false)
	events, err := readDiagnosticEvents(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != diagnosticLimit || events[0].ErrorCode != "missing-file" {
		t.Fatal("history/category wrong")
	}
	other := diagnosticTestContext(t)
	other.Role = "coordinator"
	if err := appendDiagnostic(other, "succeeded", nil); err != nil {
		t.Fatal(err)
	}
	otherRoot, _ := diagnosticRoot(other.Work, false)
	otherEvents, _ := readDiagnosticEvents(otherRoot)
	if len(otherEvents) != 1 || otherEvents[0].Role != "coordinator" {
		t.Fatal("role logs mixed")
	}
}

func TestDiagnosticsRejectsLinksAndMalformedLogs(t *testing.T) {
	c := diagnosticTestContext(t)
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(c.Work, diagnosticDirectory)); err != nil {
		t.Fatal(err)
	}
	if err := appendDiagnostic(c, "failed", errors.New("failure")); err == nil {
		t.Fatal("followed diagnostic directory link")
	}
	c = diagnosticTestContext(t)
	root, err := diagnosticRoot(c.Work, true)
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret")
	os.WriteFile(secret, []byte("secret"), 0600)
	path := filepath.Join(root, "events.json")
	os.Symlink(secret, path)
	if _, err := readDiagnosticEvents(root); err == nil {
		t.Fatal("followed diagnostic log link")
	}
	os.Remove(path)
	for _, raw := range []string{`[{"private_key":"secret"}]`, `[] {}`, strings.Repeat("x", (128<<10)+1)} {
		os.WriteFile(path, []byte(raw), 0600)
		if _, err := readDiagnosticEvents(root); err == nil {
			t.Fatal("accepted invalid log")
		}
	}
}

func TestDiagnosticsSanitizesLocallyModifiedEvents(t *testing.T) {
	c := diagnosticTestContext(t)
	root, err := diagnosticRoot(c.Work, true)
	if err != nil {
		t.Fatal(err)
	}
	e := diagnosticEvent{Time: "SECRET", Role: "SECRET", Stage: "SECRET", Action: "SECRET", Release: "SECRET", Outcome: "SECRET", ErrorCode: "SECRET", ExitCode: 999}
	raw, _ := json.Marshal([]diagnosticEvent{e})
	os.WriteFile(filepath.Join(root, "events.json"), raw, 0600)
	t.Setenv("PATH", t.TempDir())
	out := filepath.Join(t.TempDir(), "report.zip")
	if _, err := exportDiagnostics(c.Work, out); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(readReport(t, out), []byte("SECRET")) {
		t.Fatal("untrusted log values exported")
	}
}

func TestDiagnosticsPresenceDoesNotFollowArtifacts(t *testing.T) {
	work := t.TempDir()
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "ceremony.json"), []byte("secret"), 0600)
	os.Mkdir(filepath.Join(work, "ceremony"), 0700)
	os.Symlink(outside, filepath.Join(work, "ceremony/public"))
	status := diagnosticFileStatus(work)
	if status["definition"] != "symlink-not-inspected" {
		t.Fatal(status)
	}
}

func TestDiagnosticExportFromEveryRoleMenuDoesNotRunCeremony(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		t.Run(role, func(t *testing.T) {
			c := diagnosticTestContext(t)
			c.Role = role
			if err := appendDiagnostic(c, "failed", os.ErrNotExist); err != nil {
				t.Fatal(err)
			}
			f := flowFixture(t)
			f.state.Role = role
			f.state.Profile.Work = c.Work
			f.stages = roleFlowStages(role)
			out := filepath.Join(t.TempDir(), "report.zip")
			f.ui.input = bufio.NewReader(strings.NewReader("e\n" + out + "\nq\n"))
			f.run = func(flowTask, []string, string, bool) error { t.Fatal("export ran ceremony command"); return nil }
			if err := f.menu(); err != nil {
				t.Fatal(err)
			}
			if len(f.state.Attempts) != 0 {
				t.Fatal("export marked work complete")
			}
			readReport(t, out)
		})
	}
}

func TestDiagnosticExportWithoutPriorLog(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	work := t.TempDir()
	out := filepath.Join(t.TempDir(), "report.zip")
	if err := runDiagnostics([]string{"export", "--work", work, "--out", out}); err != nil {
		t.Fatal(err)
	}
	readReport(t, out)
	if _, err := os.Stat(filepath.Join(work, diagnosticDirectory)); !os.IsNotExist(err) {
		t.Fatal("export created logging/recovery state")
	}
}

func TestDiagnosticVersionOutputIsBounded(t *testing.T) {
	var out limitedDiagnosticOutput
	if _, err := io.Copy(&out, strings.NewReader(strings.Repeat("x", 100000))); err != nil {
		t.Fatal(err)
	}
	if len(out.String()) != 4096 {
		t.Fatal("version output exceeded cap")
	}
}

func TestDiagnosticExportFromOnboarding(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		t.Run(role, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "report.zip")
			input := bufio.NewReader(strings.NewReader("e\n" + out + "\n0\n"))
			if role == "coordinator" {
				w := setupFixture(t)
				w.input = input
				w.run = func([]string) error { t.Fatal("export started child"); return nil }
				if err := w.menu(); err != nil {
					t.Fatal(err)
				}
			} else {
				p := preparationFixture(t, role)
				p.ui.input = input
				p.run = func([]string) error { t.Fatal("export started child"); return nil }
				if err := p.menu(); err != nil {
					t.Fatal(err)
				}
			}
			readReport(t, out)
		})
	}
}
