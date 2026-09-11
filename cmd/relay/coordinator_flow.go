package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (w *coordinatorWizard) openCoordinatorFlow() error {
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	// The coordinator's online workflow and offline decision signer must use
	// the same ceremony name.  The latter was prepared during enrollment, so
	// deriving a second "-workflow" name here made custody signing look for a
	// different offline profile.
	name := w.d.Name
	if err := migrateLegacyCoordinatorWorkflow(root, name); err != nil {
		return err
	}
	dir, err := guidedDirectory(root, name, "coordinator")
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); errors.Is(err, os.ErrNotExist) {
		args := []string{"ceremony", "setup", name, "--role", "coordinator", "--release", w.d.Release, "--work", w.d.Work, "--trust", w.d.Trust, "--keys", w.d.Keys}
		if w.d.Credentials != "" {
			args = append(args, "--aws-credentials", w.d.Credentials)
		}
		for _, pair := range [][2]string{{"--r2-parent-credential", w.d.R2Parent}, {"--r2-control-credential", w.d.R2Control}} {
			if pair[1] != "" {
				args = append(args, pair[0], pair[1])
			}
		}
		if err := w.run(args); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	p, err := readGuidedProfile(filepath.Join(dir, "profile.json"), name, "coordinator")
	if err != nil {
		return err
	}
	if p.ReleaseCommit != strings.TrimPrefix(w.d.Release, "role-images-") || p.Work != w.d.Work || p.Trust != w.d.Trust || p.Keys != w.d.Keys {
		return errors.New("saved workflow settings differ from preparation; preserve them and review before continuing")
	}
	if err := w.refreshWorkflowCredentials(dir, p); err != nil {
		if !errors.Is(err, errCredentialsNeedRecovery) {
			return err
		}
		fmt.Fprintln(w.output, "Credential references were NOT changed. Opening the retained workflow to inspect and resolve the uncertain attempt first; do not rerun a write blindly. Return here afterward to review the credential update.")
	}
	fmt.Fprintln(w.output, "Opening the complete coordinator workflow. The existing ceremony will not be initialized again.")
	return w.run([]string{"ceremony", "guide", name, "--role", "coordinator"})
}

// migrateLegacyCoordinatorWorkflow moves the local-only profile written by
// releases which used NAME-workflow back to NAME.  Ceremony files, signed
// records and completed action history are unchanged.  It refuses ambiguity
// instead of selecting between two local profiles.
func migrateLegacyCoordinatorWorkflow(root, name string) error {
	legacyName := name + "-workflow"
	if !guidedName.MatchString(legacyName) {
		return nil // No older alias could have been created for this name.
	}
	currentDir, err := guidedDirectory(root, name, "coordinator")
	if err != nil {
		return err
	}
	legacyDir, err := guidedDirectory(root, legacyName, "coordinator")
	if err != nil {
		return err
	}
	legacyProfilePath := filepath.Join(legacyDir, "profile.json")
	legacy, err := readGuidedProfile(legacyProfilePath, legacyName, "coordinator")
	if errors.Is(err, os.ErrNotExist) {
		if _, currentErr := os.Lstat(filepath.Join(currentDir, "profile.json")); currentErr == nil || errors.Is(currentErr, os.ErrNotExist) {
			return nil
		} else {
			return currentErr
		}
	}
	if err != nil {
		return fmt.Errorf("cannot safely migrate older coordinator workflow: %w", err)
	}
	if _, err := os.Lstat(filepath.Join(currentDir, "profile.json")); err == nil {
		return errors.New("both current and older coordinator workflow profiles exist; preserve both and choose the intended profile with a maintainer")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	// Validate any retained workflow before changing its directory.  The only
	// derivable changes are the local alias and its embedded profile name.
	statePath := filepath.Join(legacyDir, "workflow", "state.json")
	var state roleFlowState
	stateExists := false
	if _, err := os.Lstat(statePath); err == nil {
		if err := setupReadJSON(statePath, &state); err != nil {
			return fmt.Errorf("cannot safely migrate older coordinator workflow state: %w", err)
		}
		if state.Schema != roleFlowSchema || state.Name != legacyName || state.Role != "coordinator" || state.Profile.Name != legacyName || state.Profile.Role != "coordinator" {
			return errors.New("older coordinator workflow state is ambiguous; preserve it and recreate the guided coordinator profile")
		}
		stateExists = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(currentDir), 0o700); err != nil {
		return err
	}
	if err := os.Rename(legacyDir, currentDir); err != nil {
		return fmt.Errorf("move older coordinator workflow: %w", err)
	}
	currentProfilePath := filepath.Join(currentDir, "profile.json")
	if err := backupPrivateFile(currentProfilePath, ".pre-custody-v1.bak"); err != nil {
		return err
	}
	legacy.Name = name
	if err := saveJSONAtomic(currentProfilePath, legacy); err != nil {
		return err
	}
	if stateExists {
		currentStatePath := filepath.Join(currentDir, "workflow", "state.json")
		if err := backupPrivateFile(currentStatePath, ".pre-custody-v1.bak"); err != nil {
			return err
		}
		state.Name = name
		state.Profile = legacy
		if err := saveJSONAtomic(currentStatePath, state); err != nil {
			return err
		}
	}
	return nil
}

func backupPrivateFile(path, suffix string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	backup := path + suffix
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("a previous migration backup exists; review it before retrying")
		}
		return fmt.Errorf("preserve local profile backup: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(backup)
		return fmt.Errorf("preserve local profile backup: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(backup)
		return fmt.Errorf("sync local profile backup: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close local profile backup: %w", err)
	}
	return nil
}
