//go:build darwin || linux

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockWorkspaceHighWater serializes the complete read/check/write transaction
// across processes sharing one role workspace. The lock file is stable; it is
// never removed because unlinking a flock file can create two lock domains.
func lockWorkspaceHighWater(path string) (func(), error) {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("workspace high-water lock is not a regular non-symlink file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("workspace high-water lock is accessible by group or other users")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect workspace high-water lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open workspace high-water lock: %w", err)
	}
	locked := false
	defer func() {
		if !locked {
			_ = file.Close()
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened workspace high-water lock: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return nil, errors.New("workspace high-water lock changed while it was opened")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("lock workspace high-water: %w", err)
	}
	locked = true
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}
