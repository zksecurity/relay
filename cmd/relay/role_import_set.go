package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ceremonyImportFiles = []struct{ kind, name string }{
	{"definition", "ceremony.json"},
	{"signature", "ceremony.sig"},
	{"coordinator", "coordinator-public-key.hex"},
}

func matchingPublicDestination(path string, raw []byte) error {
	old, err := readPreparationInput(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(old, raw) {
		return fmt.Errorf("%s already contains different bytes; preserve them and investigate", path)
	}
	return nil
}

// Publish complete bytes without replacing existing files. A crash can leave a
// matching prefix of the three-file set, never a truncated destination. Retrying
// rechecks all destinations and authenticates the full set again.
func publishPublicInput(path string, raw []byte) error {
	if err := matchingPublicDestination(path, raw); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".public-import-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(f.Name(), path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := matchingPublicDestination(path, raw); err != nil {
			return err
		}
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (p *rolePreparer) importCeremonySet() error {
	role := "decision-signer"
	if p.d.Role == "upload-station" {
		role = "upload-station"
	}
	if _, err := p.profile(role); err != nil {
		return fmt.Errorf("prepare approved images before importing the ceremony set: %w", err)
	}
	fmt.Fprintln(p.ui.output, "Ask your coordinator for ceremony.json, ceremony.sig and coordinator-public-key.hex together. Only these named public files will be read; nothing else in the folder is imported.")
	source, err := p.ui.required("Absolute path to the folder containing those three public files", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(source) || filepath.Clean(source) != source {
		return errors.New("use an absolute clean folder path")
	}
	st, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("use a directory, not a symlink")
	}
	inputs := make([][]byte, len(ceremonyImportFiles))
	for n, file := range ceremonyImportFiles {
		inputs[n], err = readPreparationInput(filepath.Join(source, file.name))
		if err != nil {
			return fmt.Errorf("read %s: %w", file.name, err)
		}
		if n < 2 && !json.Valid(inputs[n]) {
			return fmt.Errorf("%s must be the public JSON artifact", file.name)
		}
		if err := matchingPublicDestination(preparationDestination(p.d, file.kind), inputs[n]); err != nil {
			return err
		}
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(inputs[2])))
	if err != nil || len(key) != 32 {
		return errors.New("expected a 32-byte coordinator public key encoded as hex")
	}
	fmt.Fprintf(p.ui.output, "Coordinator public-key fingerprint: sha256:%x\nA key received alongside the signature does not establish the coordinator's identity.\n", sha256.Sum256(key))
	if err := p.ui.confirm("Compare this fingerprint with the coordinator through your independent channel, not the file's download page", "VERIFIED"); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(p.d.Work, "ceremony-import-")
	if err != nil {
		return err
	}
	// Retain staging: saved read-only inspection actions refer to these exact paths.
	for n, file := range ceremonyImportFiles {
		if err := publishPublicInput(filepath.Join(stage, file.name), inputs[n]); err != nil {
			return err
		}
	}
	base := "/work/" + filepath.Base(stage)
	if err := p.open(role, filepath.Base(stage), []string{"mpc-ceremony", "inspect", "definition", "--ceremony", base + "/ceremony.json", "--ceremony-signature", base + "/ceremony.sig", "--coordinator-public-key-file", base + "/coordinator-public-key.hex"}); err != nil {
		return fmt.Errorf("ceremony set not imported; inspection did not succeed (public staging retained at %s): %w", stage, err)
	}
	for n, file := range ceremonyImportFiles {
		raw, err := readPreparationInput(filepath.Join(stage, file.name))
		if err != nil {
			return err
		}
		if !bytes.Equal(raw, inputs[n]) {
			return errors.New("staged public files changed during inspection; nothing further imported")
		}
		if err := matchingPublicDestination(preparationDestination(p.d, file.kind), inputs[n]); err != nil {
			return err
		}
	}
	for n, file := range ceremonyImportFiles {
		if err := publishPublicInput(preparationDestination(p.d, file.kind), inputs[n]); err != nil {
			return fmt.Errorf("import interrupted; matching files retained, retry this same set: %w", err)
		}
	}
	fmt.Fprintln(p.ui.output, "All three files imported. The definition signature was verified against the coordinator key you independently confirmed. Enrollment, assignment acceptance and storage readiness are separate steps.")
	return nil
}
