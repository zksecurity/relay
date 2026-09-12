package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoordinatorPreparationRecommendations(t *testing.T) {
	for _, tc := range []struct {
		name, choice string
		change       func(*coordinatorWizard)
	}{
		{"basics", "1", func(w *coordinatorWizard) { w.d.Mode = "" }},
		{"new identity", "2", func(w *coordinatorWizard) {
			w.d.Identities.Coordinator = setupIdentity{}
			if err := os.Remove(filepath.Join(w.d.Keys, "signing.hex")); err != nil {
				t.Fatal(err)
			}
		}},
		{"recover identity", "3", func(w *coordinatorWizard) { w.d.Identities.Coordinator = setupIdentity{} }},
		{"missing auditor", "3", func(w *coordinatorWizard) { w.d.Identities.Auditors = nil }},
		{"duplicate key", "3", func(w *coordinatorWizard) { w.d.Identities.ReleaseSigner = w.d.Identities.Coordinator }},
		{"invalid policy", "4", func(w *coordinatorWizard) { w.d.Policy.Phase1.Minimum = 0 }},
		{"invalid architecture", "5", func(w *coordinatorWizard) { w.d.ArchitecturePolicy = "invalid" }},
		{"storage", "6", func(w *coordinatorWizard) {}},
		{"offline exception", "8", func(w *coordinatorWizard) { w.d.OfflinePreparation = true }},
		{"local initialize", "8", func(w *coordinatorWizard) { w.localAction = func(string, string, []string, bool) error { return nil } }},
		{"recovery", "8", func(w *coordinatorWizard) { w.d.Status = "initialization-attempted" }},
		{"enrollment", "13", func(w *coordinatorWizard) { w.d.Status = "definition-verified" }},
		{"local complete", "0", func(w *coordinatorWizard) {
			w.d.Status = "definition-verified"
			w.localAction = func(string, string, []string, bool) error { return nil }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := setupFixture(t)
			tc.change(&w)
			got := w.nextPreparationAction()
			if got.choice != tc.choice {
				t.Fatalf("got %#v, want %s", got, tc.choice)
			}
			if got.reason == "" || got.label == "" {
				t.Fatal("missing explanation")
			}
			if strings.HasPrefix(got.reason, "Required:") {
				t.Fatalf("generic requirement prefix leaked into %s: %q", tc.name, got.reason)
			}
			w.output = new(bytes.Buffer)
			w.preparationHeading(got)
			if out := w.output.(*bytes.Buffer).String(); !strings.Contains(out, "WHY THIS STEP IS NEEDED") || !strings.Contains(out, got.reason) {
				t.Fatalf("preparation reason not rendered clearly: %s", out)
			}
		})
	}
}

func TestCoordinatorPreparationCompactMenuAndExplicitOtherActions(t *testing.T) {
	w := setupFixture(t)
	w.input = bufio.NewReader(strings.NewReader("0\n"))
	if err := w.menu(); err != nil {
		t.Fatal(err)
	}
	out := w.output.(*bytes.Buffer).String()
	for _, expected := range []string{"NEXT REQUIRED ACTION", "WHY THIS STEP IS NEEDED", "Online operations need verified storage settings", "6) Set up storage", "17) Show other actions and requirements", "0) Save and exit"} {
		if !strings.Contains(out, expected) {
			t.Fatal("missing", expected, out)
		}
	}
	if strings.Contains(out, "8) Review and approve") {
		t.Fatal("long menu shown by default")
	}
	w.output = new(bytes.Buffer)
	w.input = bufio.NewReader(strings.NewReader("17\n0\n"))
	if err := w.menu(); err != nil {
		t.Fatal(err)
	}
	out = w.output.(*bytes.Buffer).String()
	for _, expected := range []string{"OTHER ACTIONS AND REQUIREMENTS", "[Required settings]", "[Optional; both architectures by default]", "explicit offline preparation available"} {
		if !strings.Contains(out, expected) {
			t.Fatal("missing", expected, out)
		}
	}
	if strings.Contains(out, "9) Verify existing") || strings.Contains(out, "10) Configure storage") {
		t.Fatal("inapplicable pre-initialization actions shown")
	}
}

func TestCoordinatorPreparationFilesAreNotVerifiedCompletion(t *testing.T) {
	w := setupFixture(t)
	w.d.Status = "definition-verified"
	dir := filepath.Join(w.d.Work, "my-enrollment")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"canonical.json", "enrollment.sig"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("not verified"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	next := w.nextPreparationAction()
	if next.choice != "12" || !strings.Contains(next.reason, "menu has not verified") {
		t.Fatal(next)
	}
	w.d.Status = "initialization-attempted"
	if next = w.nextPreparationAction(); next.choice != "8" {
		t.Fatal("existing files bypassed recovery", next)
	}
}

func TestCoordinatorPreparationDoesNotExecuteHiddenChoice(t *testing.T) {
	w := setupFixture(t)
	w.run = func([]string) error { t.Fatal("hidden action executed"); return nil }
	w.input = bufio.NewReader(strings.NewReader("8\n0\n"))
	if err := w.menu(); err != nil {
		t.Fatal(err)
	}
	if w.d.Status != "draft" || !strings.Contains(w.output.(*bytes.Buffer).String(), "Choose a displayed action") {
		t.Fatal("hidden action accepted")
	}
}
