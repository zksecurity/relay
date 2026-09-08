package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zksecurity/relay/contracts/setupv2"
	"os"
	"path/filepath"
)

func checkTesseraDraft(d coordinatorDraft) error {
	if d.TesseraSetup != nil {
		return checkSetupDraftV2(d)
	}
	if d.Tessera == nil {
		return errors.New("import the Tessera roster first")
	}
	if err := d.Tessera.validate(); err != nil {
		return err
	}
	roster, p1, p2 := d.Tessera.setupInputs()
	actual, _ := json.Marshal([]any{d.Mode, d.Identities, d.Policy.Phase1, d.Policy.Phase2})
	expected, _ := json.Marshal([]any{d.Tessera.Mode, roster, p1, p2})
	if !bytes.Equal(actual, expected) {
		return errors.New("local roles, mode or orders changed since Tessera import; update the website and import its fresh roster before initialization")
	}
	return nil
}
func (w *coordinatorWizard) importTesseraRoster() error {
	if w.d.Status != "draft" {
		return errors.New("Tessera roster cannot change after initialization has been attempted")
	}
	path, err := w.required("Path to roster JSON downloaded from Tessera", "")
	if err != nil {
		return err
	}
	raw, err := readTesseraRegularFile(path, setupv2.MaxBytes, false)
	if err != nil {
		return err
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if err = json.Unmarshal(raw, &header); err != nil {
		return err
	}
	if header.Schema == "ceremony-setup-v2" {
		return w.importSetupV2(path, raw)
	}
	c, err := loadTesseraContext(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(w.output, "Website ceremony %s, revision %d (%s)\n", c.CeremonyID, c.Revision, c.Mode)
	for _, a := range c.Assignments {
		fmt.Fprintf(w.output, "%s: %q · %s\n", a.Role, a.Identity.DisplayName, a.Identity.Fingerprint)
	}
	fmt.Fprintln(w.output, "This replaces local draft identities, mode, orders and minima. Compare public fingerprints with their owners. Circuit and beacon policy still need your review. Witness/mirror assignments are retained for the website and enrolled separately after initialization.")
	if err = w.confirm("Accept this roster and its reviewed fingerprints", "IMPORT ROSTER"); err != nil {
		return err
	}
	previous := w.d
	w.d.Tessera = &c
	w.d.Mode = c.Mode
	w.d.Identities, w.d.Policy.Phase1, w.d.Policy.Phase2 = c.setupInputs()
	if err = w.save(); err != nil {
		w.d = previous
		return err
	}
	fmt.Fprintln(w.output, "Roster imported. Review Basics and beacon policy, then choose Review draft and Approve and initialize. Export setup for Tessera becomes available after verification.")
	return nil
}
func (w *coordinatorWizard) exportTesseraSetup() error {
	if w.d.Status != "definition-verified" || w.localAction != nil {
		return errors.New("export requires a verified definition and an approved CLI release")
	}
	if err := checkTesseraDraft(w.d); err != nil {
		return err
	}
	if w.d.TesseraSetup != nil {
		return w.exportSetupV2()
	}
	storage := tesseraStorage{Provider: w.d.Storage["provider"], Region: w.d.Storage["region"], PublicURL: w.d.Storage["published-base-url"], PublishedBucket: w.d.Storage["published-bucket"], InboxBucket: w.d.Storage["inbox-bucket"]}
	if err := storage.validate(); err != nil {
		return err
	}
	out, err := w.required("Fresh output JSON path for Tessera", filepath.Join(w.d.Work, "tessera-setup.json"))
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "tessera-context-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	contextPath, storagePath := filepath.Join(dir, "roster.json"), filepath.Join(dir, "storage.json")
	if err = setupWriteNew(contextPath, w.d.Tessera); err != nil {
		return err
	}
	if err = setupWriteNew(storagePath, storage); err != nil {
		return err
	}
	return runTesseraExport([]string{"--context", contextPath, "--ceremony", filepath.Join(w.d.Work, "ceremony/public/ceremony.json"), "--ceremony-signature", filepath.Join(w.d.Work, "ceremony/public/ceremony.sig"), "--coordinator-key-file", filepath.Join(w.d.Trust, "setup-coordinator.hex"), "--release", w.d.Release, "--storage-public", storagePath, "--out", out})
}
