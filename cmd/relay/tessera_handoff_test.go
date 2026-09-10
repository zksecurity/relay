package main

import (
	"bufio"
	"bytes"
	setupv2 "github.com/zksecurity/relay/contracts/setupv2r2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTesseraHandoffResumeAndLostExport(t *testing.T) {
	w := setupFixture(t)
	w.d.Status = "definition-verified"
	w.d.TesseraSetup = &setupv2.Setup{}
	if got := w.nextPreparationAction().choice; got != "13" {
		t.Fatal(got)
	}
	dir := filepath.Join(w.d.Work, "my-enrollment")
	os.MkdirAll(dir, 0700)
	for _, n := range []string{"canonical.json", "enrollment.sig"} {
		os.WriteFile(filepath.Join(dir, n), []byte("navigation fixture, not verified"), 0600)
	}
	if got := w.nextPreparationAction().choice; got != "16" {
		t.Fatal(got)
	}
	path := filepath.Join(w.d.Work, "tessera-setup.json")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 2<<20), 0600)
	if err := w.recordTesseraExport(path); err != nil {
		t.Fatal(err)
	}
	if !w.tesseraExportPresent() || w.nextPreparationAction().choice != "0" {
		t.Fatal("missing export checkpoint")
	}
	if w.tesseraExportDefault() == path {
		t.Fatal("repeat would default to existing file")
	}
	var loaded coordinatorDraft
	if err := setupReadJSON(w.draftPath, &loaded); err != nil {
		t.Fatal(err)
	}
	w.d = loaded
	if !w.tesseraExportPresent() {
		t.Fatal("resume lost export")
	}
	w.input = bufio.NewReader(strings.NewReader("0\n"))
	w.output = new(bytes.Buffer)
	if err := w.menu(); err != nil {
		t.Fatal(err)
	}
	out := w.output.(*bytes.Buffer).String()
	for _, text := range []string{"NEXT STEP — RETURN TO TESSERA", "Export again", "Continue to ceremony operations", "website acceptance is not checked"} {
		if !strings.Contains(out, text) {
			t.Fatal(text, out)
		}
	}
	os.WriteFile(path, []byte("changed"), 0600)
	if w.tesseraExportPresent() || w.nextPreparationAction().choice != "16" {
		t.Fatal("changed export trusted")
	}
	os.Remove(path)
	if w.tesseraExportPresent() {
		t.Fatal("missing export trusted")
	}
	w.d.Status = "initialization-attempted"
	if w.nextPreparationAction().choice != "9" {
		t.Fatal("recovery bypass")
	}
}
func TestSetupImportRecognizesPrivateConnection(t *testing.T) {
	w := setupFixture(t)
	path := filepath.Join(w.d.Work, "connection.json")
	os.WriteFile(path, []byte(`{"schema":"tessera-cli-connection-v1","token":"PRIVATE"}`), 0600)
	w.input = bufio.NewReader(strings.NewReader(path + "\n"))
	err := w.importTesseraRoster()
	if err == nil || !strings.Contains(err.Error(), "Storage settings") || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal(err)
	}
}
func TestDisclosurePresets(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"1\ncoordinator and auditor\none Mac, Example Ltd\n\n", "I operate coordinator and auditor"},
		{"2\nExample Ltd\nshared server\nwitness\n\n", "roles sharing the organization or equipment are: witness"},
		{"3\nExample Ltd\n\n", "To my knowledge"},
		{"3\nnone\nMy edited statement\n", "My edited statement"},
		{"4\nCustom disclosure\n", "Custom disclosure"},
	} {
		w := setupFixture(t)
		w.input = bufio.NewReader(strings.NewReader(tc.input))
		p := rolePreparer{d: rolePreparation{Role: "auditor"}, ui: w}
		text, err := p.disclosurePreset()
		if err != nil || !strings.Contains(text, tc.want) {
			t.Fatal(text, err)
		}
	}
	w := setupFixture(t)
	w.input = bufio.NewReader(strings.NewReader("3\n\n"))
	p := rolePreparer{d: rolePreparation{Role: "auditor"}, ui: w}
	if _, err := p.disclosurePreset(); err == nil {
		t.Fatal("missing affiliation accepted")
	}
}
