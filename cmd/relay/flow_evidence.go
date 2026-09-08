package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// These are file bindings for local progress, not replacement verification.
// Never inspect keys, grant credentials, or arbitrary directory trees here.
func flowEvidenceField(field flowField) bool {
	if field.Kind != "path" {
		return false
	}
	switch field.Flag {
	case "signing-key", "coordinator-signing-key", "auditor-signing-key", "grant", "environment", "out":
		return false
	}
	return !strings.HasPrefix(field.Default, "/keys/")
}

func (f *roleFlow) captureEvidence(task flowTask, command []string) (map[string]string, error) {
	bindings := map[string]string{}
	if f.state.Profile.Work == "" {
		return bindings, nil
	}
	fields := append(append([]flowField{}, task.Fields...), task.ExtraFields...)
	if task.ID == "submit" && (f.state.Role == "mirror" || f.state.Role == "witness") {
		dir := commandValue(command, "dir")
		for _, name := range []string{"canonical.json", "receipt.sig"} {
			value := strings.TrimSuffix(dir, "/") + "/" + name
			local, err := f.publicHostPath(value)
			if err != nil {
				return nil, err
			}
			digest, err := setupFileHash(local)
			if err != nil {
				return nil, err
			}
			bindings[value] = digest
		}
	}
	for _, field := range fields {
		if !flowEvidenceField(field) || flowOutputField(task, field) {
			continue
		}
		for n, arg := range command {
			if arg != "--"+field.Flag || n+1 >= len(command) {
				continue
			}
			value := command[n+1]
			if strings.HasPrefix(value, "/keys/") {
				continue
			}
			local, err := f.publicHostPath(value)
			if err != nil {
				return nil, err
			}
			st, err := os.Lstat(local)
			if err != nil {
				return nil, fmt.Errorf("required %s is unavailable: %w", field.Label, err)
			}
			if st.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("evidence input must not be a symlink")
			}
			// Directory completeness remains the command verifier's responsibility.
			if st.IsDir() {
				continue
			}
			if !st.Mode().IsRegular() {
				return nil, errors.New("evidence input is not a regular file")
			}
			digest, err := setupFileHash(local)
			if err != nil {
				return nil, err
			}
			bindings[value] = digest
		}
	}
	return bindings, nil
}

func (f *roleFlow) checkAttemptEvidence(a *flowAttempt) error {
	if a == nil || f.state.Profile.Work == "" {
		return nil
	}
	for value, digest := range a.InputBindings {
		local, err := f.publicHostPath(value)
		if err != nil {
			return err
		}
		got, err := setupFileHash(local)
		if err != nil || got != digest {
			return fmt.Errorf("previous action input changed or is missing: %s; inspect retained output and reverify", value)
		}
	}
	return f.checkDirectoryBindings(a.DirectoryBindings)
}
