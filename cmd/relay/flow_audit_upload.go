package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Copy only the exact successful audit pair, never a recursive workspace.
// A retry accepts identical files and rejects conflicts or extra material.
func (f *roleFlow) prepareAuditUpload(task flowTask) (flowTask, error) {
	if f.state.Role != "auditor" || task.ID != "submit" || f.state.Profile.Work == "" {
		return task, nil
	}
	a := f.last(flowTask{ID: "audit"})
	if a == nil || a.Status != "succeeded" {
		return task, errors.New("complete your audit first; its exact report and signature are required for upload")
	}
	if err := f.checkAttemptEvidence(a); err != nil {
		return task, err
	}
	if !validFlowAttemptID(strings.TrimPrefix(a.ID, "flow-")) {
		return task, errors.New("invalid saved audit attempt identity")
	}
	dir := "/work/audit-upload-" + a.ID
	local, err := f.publicHostPath(dir)
	if err != nil {
		return task, err
	}
	contents := map[string][]byte{}
	for flag, name := range map[string]string{"out": "audit.json", "audit-signature": "audit.sig"} {
		source, err := f.publicHostPath(commandValue(a.Command, flag))
		if err != nil {
			return task, err
		}
		raw, err := readPreparationInput(source)
		if err != nil {
			return task, err
		}
		contents[name] = raw
	}
	if err := os.Mkdir(local, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return task, err
	}
	st, err := os.Lstat(local)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return task, errors.New("audit upload folder must be a real directory")
	}
	entries, err := os.ReadDir(local)
	if err != nil {
		return task, err
	}
	for _, entry := range entries {
		if _, ok := contents[entry.Name()]; !ok {
			return task, errors.New("audit upload folder contains additional files; inspect it without deleting or uploading those files")
		}
	}
	for name, raw := range contents {
		path := filepath.Join(local, name)
		if old, err := readPreparationInput(path); err == nil {
			if !bytes.Equal(old, raw) {
				return task, errors.New("audit upload folder conflicts with the exact signed audit; retain and investigate")
			}
		} else if errors.Is(err, os.ErrNotExist) {
			if err := writePublicTextOnce(path, string(raw)); err != nil {
				return task, err
			}
		} else {
			return task, err
		}
	}
	// Do not mutate the catalog's shared field slice.
	task.Fields = append([]flowField(nil), task.Fields...)
	for i := range task.Fields {
		if task.Fields[i].Flag == "dir" {
			task.Fields[i].Default = dir
		}
	}
	fmt.Fprintf(f.ui.output, "Prepared PUBLIC audit upload folder: %s\nContains only your exact report and signature. Your private key was not copied.\n", local)
	return task, nil
}
