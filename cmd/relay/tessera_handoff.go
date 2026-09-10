package main

import (
	"crypto/sha256"
	"fmt"
	setupv2 "github.com/zksecurity/relay/contracts/setupv2r2"
	"os"
	"path/filepath"
	"time"
)

// This receipt is local navigation state, never website acceptance evidence.
func (w *coordinatorWizard) tesseraExportPresent() bool {
	if w.d.Tessera == nil && w.d.TesseraSetup == nil {
		return false
	}
	if w.d.TesseraExportPath == "" || w.d.TesseraExportSHA256 == "" {
		return false
	}
	raw, err := readTesseraRegularFile(w.d.TesseraExportPath, setupv2.MaxBytes, false)
	return err == nil && fmt.Sprintf("%x", sha256.Sum256(raw)) == w.d.TesseraExportSHA256
}
func (w *coordinatorWizard) recordTesseraExport(out string) error {
	path, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	raw, err := readTesseraRegularFile(path, setupv2.MaxBytes, false)
	if err != nil {
		return err
	}
	oldPath, oldHash := w.d.TesseraExportPath, w.d.TesseraExportSHA256
	w.d.TesseraExportPath = path
	w.d.TesseraExportSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	if err = w.save(); err != nil {
		w.d.TesseraExportPath = oldPath
		w.d.TesseraExportSHA256 = oldHash
		return fmt.Errorf("setup exported to %s but navigation state could not be saved; preserve the file: %w", path, err)
	}
	w.message(toneSuccess, "\nSetup exported to: %s\n", path)
	fmt.Fprintln(w.output, "Next: upload this file to your Tessera ceremony. Then review and lock the setup on the website. The CLI has not checked website acceptance. Keep your local workspace and signing key.")
	return nil
}

func (w *coordinatorWizard) tesseraExportDefault() string {
	path := filepath.Join(w.d.Work, "tessera-setup.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return path
	}
	return filepath.Join(w.d.Work, fmt.Sprintf("tessera-setup-%d.json", time.Now().UnixNano()))
}
