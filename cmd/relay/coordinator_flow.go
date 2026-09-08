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
	name := w.d.Name + "-workflow"
	if !guidedName.MatchString(name) {
		return errors.New("ceremony name too long for workflow alias")
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
