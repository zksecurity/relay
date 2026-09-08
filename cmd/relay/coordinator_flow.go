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
	if p.ReleaseCommit != strings.TrimPrefix(w.d.Release, "role-images-") || p.Work != w.d.Work || p.Trust != w.d.Trust || p.Keys != w.d.Keys || p.Credentials != w.d.Credentials {
		return errors.New("saved workflow settings differ from preparation; preserve them and review before continuing")
	}
	fmt.Fprintln(w.output, "Opening the complete coordinator workflow. The existing ceremony will not be initialized again.")
	return w.run([]string{"ceremony", "guide", name, "--role", "coordinator"})
}
