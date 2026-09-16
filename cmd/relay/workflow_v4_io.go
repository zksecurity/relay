package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

const workflowV4MaximumBytes = 16 << 20

// readWorkflowV4JSON reads private local recovery state, not authenticated
// ceremony evidence. Callers must additionally validate its schema and bindings.
// The workspace lock must be held throughout reading and any later mutation.
func readWorkflowV4JSON(path string, target any) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() > workflowV4MaximumBytes {
		return errors.New("V4 recovery state must be a private regular file within its size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(before, opened) {
		return errors.New("V4 recovery state changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, workflowV4MaximumBytes+1))
	if err != nil {
		return err
	}
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if len(raw) > workflowV4MaximumBytes || int64(len(raw)) != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return errors.New("V4 recovery state changed or exceeded its size limit")
	}
	if err := rejectCommitJournalDuplicateFields(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("V4 recovery state has trailing JSON")
	}
	return nil
}
