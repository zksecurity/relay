package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/access"
)

func receiveEvidence(ceremony, role, key, out string, manifest access.SubmissionManifest, get func(string, string, int64) error) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	prefix, err := access.Prefix(ceremony, manifest.Role, manifest.IdentityID)
	if err != nil {
		return err
	}
	prefix += manifest.AttemptID + "/"
	if manifest.CeremonyID != ceremony || (role != "" && role != manifest.Role) || key != prefix+"manifest.json" {
		return errors.New("evidence manifest scope does not match ceremony, role or object key")
	}
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return errors.New("use a fresh absolute evidence review directory")
	}
	if err := validateRoleMount(filepath.Dir(out), false); err != nil {
		return err
	}
	if _, err := os.Lstat(out + ".receipt.json"); !os.IsNotExist(err) {
		return errors.New("evidence receipt destination must also be fresh")
	}
	if len(manifest.Files) > 10000 {
		return errors.New("too many evidence files")
	}
	var total int64
	for _, ref := range manifest.Files {
		total += ref.Size
		if ref.Size > 16<<30 || total < 0 || total > 16<<30 || ref.Name == ".relay-received-manifest.json" || flowPrivateBasename(ref.Name) {
			return errors.New("evidence exceeds review limits or contains a reserved/private filename")
		}
	}
	if err := os.Mkdir(out, 0700); err != nil {
		return err
	}
	// Preserve partial downloads after any failure. A retry must use a fresh
	// directory; it must not silently overwrite or mark partial evidence complete.
	for _, ref := range manifest.Files {
		local := filepath.Join(out, filepath.FromSlash(ref.Name))
		if !strings.HasPrefix(local, out+string(filepath.Separator)) {
			return errors.New("evidence path escapes review directory")
		}
		if err := os.MkdirAll(filepath.Dir(local), 0700); err != nil {
			return err
		}
		if err := get(prefix+"files/"+ref.Name, local, ref.Size); err != nil {
			return fmt.Errorf("download incomplete; retain %s for investigation: %w", out, err)
		}
		got, err := regularFileRef(local, ref.Name)
		if err != nil {
			return err
		}
		if got != ref {
			return errors.New("downloaded evidence differs from manifest; retain partial directory and do not use it")
		}
	}
	// Keep transport metadata outside the bundle: final release verification
	// rejects additional unlisted files inside the signed release tree.
	return writeJSONNoReplace(out+".receipt.json", manifest, 0600)
}
