package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

var errCredentialsNeedRecovery = errors.New("inspect and resolve uncertain workflow attempts before changing its credentials")

func sameProfileExceptCredentials(a, b guidedProfile) bool {
	a.Credentials, a.R2Parent, a.R2Control = "", "", ""
	b.Credentials, b.R2Parent, b.R2Control = "", "", ""
	return reflect.DeepEqual(a, b)
}

// Rotate only credential references, never images, release pins, identities or
// ceremony bindings. Preserve the previous profile and all operation attempts.
func (w *coordinatorWizard) refreshWorkflowCredentials(dir string, p guidedProfile) error {
	next := p
	next.Credentials, next.R2Parent, next.R2Control = w.d.Credentials, w.d.R2Parent, w.d.R2Control
	needsRefresh := !reflect.DeepEqual(next, p)
	statePath := filepath.Join(dir, "workflow", "state.json")
	flowLock, err := acquireParticipantRunLock(statePath, filepath.Dir(statePath))
	if err != nil {
		return err
	}
	defer flowLock.release()
	profilePath := filepath.Join(dir, "profile.json")
	profileLock, err := acquireParticipantRunLock(profilePath, filepath.Join(dir, "activity"))
	if err != nil {
		return err
	}
	defer profileLock.release()
	current, err := readGuidedProfile(profilePath, p.Name, p.Role)
	if err != nil || !reflect.DeepEqual(current, p) {
		return errors.New("saved profile changed; reopen preparation before refreshing credentials")
	}
	var state roleFlowState
	hasState := false
	if _, err := os.Lstat(statePath); err == nil {
		if err := setupReadJSON(statePath, &state); err != nil {
			return err
		}
		if state.Schema != roleFlowSchema || !sameProfileExceptCredentials(state.Profile, p) {
			return errors.New("workflow differs beyond credentials; do not migrate automatically")
		}
		needsRefresh = needsRefresh || !reflect.DeepEqual(state.Profile, next)
		if !needsRefresh {
			return nil
		}
		latest := map[string]flowAttempt{}
		for _, a := range state.Attempts {
			latest[a.Stage+"/"+a.Task] = a
		}
		for _, a := range latest {
			if a.Status == "running" || a.Status == "failed" {
				return errCredentialsNeedRecovery
			}
		}
		hasState = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if !needsRefresh {
		return nil
	}
	if _, err := dockerRoleArgs(next.options(), []string{"relay", "coordinator", "check-storage"}, os.Getuid(), os.Getgid()); err != nil {
		return fmt.Errorf("new credential files are unavailable or unsafe: %w", err)
	}
	if err := w.confirm("Update only the saved workflow's credential FILE references. Keep all history, keys, release and ceremony unchanged. This does not refresh previous storage checks or revoke old credentials", "UPDATE CREDENTIAL REFERENCES"); err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	if err := setupWriteNew(filepath.Join(dir, "credentials-before-"+id+".json"), p); err != nil {
		return err
	}
	if err := saveJSONAtomic(profilePath, next); err != nil {
		return err
	}
	if hasState {
		state.Profile = next
		state.Attempts = append(state.Attempts, flowAttempt{ID: id, Task: "credential-references", Stage: "settings", Status: "reported", Note: "Operator approved new credential references; previous verification timestamps were not refreshed.", FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		if err := saveJSONAtomic(statePath, state); err != nil {
			return errors.New("profile updated but workflow checkpoint failed; preserve files and repeat credential-reference review to reconcile")
		}
	}
	return nil
}
