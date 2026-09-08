//go:build darwin || linux

package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type participantRunLock struct {
	file *os.File
}

func acquireParticipantRunLock(configPath, candidateParent string) (*participantRunLock, error) {
	if err := ensurePrivateDirectory(candidateParent); err != nil {
		return nil, fmt.Errorf("prepare participant run lock directory: %w", err)
	}
	absoluteConfig, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("resolve participant profile for locking: %w", err)
	}
	digest := sha256.Sum256([]byte(filepath.Clean(absoluteConfig)))
	path := filepath.Join(candidateParent, fmt.Sprintf(".relay-participant-run-%x.lock", digest[:16]))
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("participant run lock is not a regular non-symlink file")
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("participant run lock is accessible by group or other users")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect participant run lock: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open participant run lock: %w", err)
	}
	locked := false
	defer func() {
		if !locked {
			_ = file.Close()
		}
	}()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened participant run lock: %w", err)
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return nil, errors.New("participant run lock changed while it was opened")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another Relay helper or run is already active for this profile in %s; return to its terminal or save and exit there before reopening; do not delete the lock file", candidateParent)
		}
		return nil, fmt.Errorf("lock participant profile: %w", err)
	}
	locked = true
	return &participantRunLock{file: file}, nil
}

func (l *participantRunLock) release() error {
	if l == nil || l.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	if unlockErr != nil {
		return fmt.Errorf("unlock participant profile: %w", unlockErr)
	}
	return closeErr
}
