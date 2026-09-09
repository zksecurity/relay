package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/verification"
)

// Packing uses an explicit list of public files. It never recursively collects a
// ceremony workspace, which could contain keys and temporary upload credentials.
func runPackCeremony(args []string) error {
	f := flag.NewFlagSet("pack-ceremony", flag.ContinueOnError)
	descriptor := f.String("manifest", "", "verification manifest with explicitly selected public file paths")
	root := f.String("root", "", "public evidence root")
	out := f.String("out", "", "fresh output ZIP")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *descriptor == "" || *root == "" || *out == "" || f.NArg() != 0 {
		return errors.New("--manifest, --root and --out are required")
	}
	raw, err := readTesseraRegularFile(*descriptor, verification.MaxManifest, false)
	if err != nil {
		return err
	}
	m, err := access.Decode(raw, func(m verification.Manifest) error {
		if len(m.Files) == 0 || len(m.Files) > verification.MaxFiles {
			return errors.New("explicit public file inventory required")
		}
		return nil
	})
	if err != nil {
		return err
	}
	return packCeremony(*root, *out, m)
}
func packCeremony(root, out string, m verification.Manifest) (err error) {
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	// os.Root prohibits traversal outside the selected directory, including symlinks.
	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	for index, item := range m.Files {
		if !verification.SafePath(item.Path) {
			return fmt.Errorf("unsafe public file %q", item.Path)
		}
		for parent := item.Path; parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			info, e := r.Lstat(parent)
			if e != nil {
				return e
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("public file paths cannot contain symlinks")
			}
		}
		file, e := r.Open(item.Path)
		if e != nil {
			return e
		}
		info, e := file.Stat()
		if e != nil || !info.Mode().IsRegular() {
			file.Close()
			return errors.New("public inventory requires regular files")
		}
		h := sha256.New()
		n, e := io.Copy(h, file)
		file.Close()
		if e != nil {
			return e
		}
		m.Files[index].Size = n
		m.Files[index].SHA256 = hex.EncodeToString(h.Sum(nil))
		if item.Path == m.Inputs["ceremony"] {
			m.DefinitionSHA256 = m.Files[index].SHA256
		}
	}
	if err = m.Validate(); err != nil {
		return err
	}
	output, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() {
		output.Close()
		if err != nil {
			os.Remove(out)
		}
	}()
	z := zip.NewWriter(output)
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	w, err := z.Create("verification.json")
	if err != nil {
		return err
	}
	if _, err = w.Write(raw); err != nil {
		return err
	}
	for _, item := range m.Files {
		input, e := r.Open(item.Path)
		if e != nil {
			return e
		}
		// Store avoids spending hours compressing high-entropy proving material.
		header := &zip.FileHeader{Name: item.Path, Method: zip.Store}
		header.SetMode(0600)
		w, e := z.CreateHeader(header)
		if e != nil {
			input.Close()
			return e
		}
		h := sha256.New()
		n, e := io.Copy(io.MultiWriter(w, h), io.LimitReader(input, item.Size+1))
		input.Close()
		if e != nil {
			return e
		}
		if n != item.Size || !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), item.SHA256) {
			return fmt.Errorf("public evidence changed during export: %s", item.Path)
		}
	}
	if err = z.Close(); err != nil {
		return err
	}
	return output.Close()
}
