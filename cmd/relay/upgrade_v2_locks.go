package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Old entry points lock either preparation or saved-profile activity, whereas
// the storage-first guide locks Work. Hold all existing matching locks during
// activation; otherwise an old enrollment helper can race the inventory.
func upgradeV2LockRelated(p guidedProfile, root, alreadyLocked string) (func(), error) {
	var locks []*participantRunLock
	release := func() {
		for n := len(locks) - 1; n >= 0; n-- {
			_ = locks[n].release()
		}
	}
	acquire := func(path string) error {
		l, err := acquireParticipantRunLock("", path)
		if err != nil {
			return err
		}
		locks = append(locks, l)
		return nil
	}
	if _, err := os.Lstat(upgradeV2Root(p.Work)); err == nil {
		if err := acquire(filepath.Join(upgradeV2Root(p.Work), "setup-activity")); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, name := range []string{"coordinator-setup", "role-preparation"} {
		dir := filepath.Join(p.Work, name)
		if info, err := os.Lstat(dir); err == nil {
			if !info.IsDir() {
				release()
				return nil, errors.New("preparation folder is not a directory")
			}
			if err := acquire(dir); err != nil {
				release()
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			release()
			return nil, err
		}
	}
	names, err := os.ReadDir(root)
	if err != nil {
		release()
		return nil, err
	}
	if len(names) > 4096 {
		release()
		return nil, errors.New("too many saved profiles to inventory safely")
	}
	for _, name := range names {
		if !name.IsDir() {
			continue
		}
		roles, err := os.ReadDir(filepath.Join(root, name.Name()))
		if err != nil {
			release()
			return nil, err
		}
		for _, role := range roles {
			if !role.IsDir() {
				continue
			}
			dir := filepath.Join(root, name.Name(), role.Name())
			profile, err := readGuidedProfile(filepath.Join(dir, "profile.json"), name.Name(), role.Name())
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				release()
				return nil, fmt.Errorf("cannot establish saved-profile exclusion: %w", err)
			}
			if profile.Work != p.Work && !(profile.Role == "keygen" && profile.Work == p.Keys && profile.ReleaseCommit == p.ReleaseCommit) {
				continue
			}
			if dir != alreadyLocked {
				if err := acquire(filepath.Join(dir, "activity")); err != nil {
					release()
					return nil, err
				}
			}
			// A saved action without a completion marker might still have a child. It
			// is not made safe merely by an empty generic V4 journal.
			err = filepath.WalkDir(dir, func(path string, e fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if e.Type()&os.ModeSymlink != 0 {
					return errors.New("symlink in saved activity")
				}
				if e.IsDir() && e.Name() == "activity" {
					if err := checkGuidedAttempts(path); err != nil {
						return fmt.Errorf("resolve retained saved action under its original application before updating: %w", err)
					}
					return filepath.SkipDir
				}
				return nil
			})
			if err != nil {
				release()
				return nil, err
			}
		}
	}
	return release, nil
}
