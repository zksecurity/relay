//go:build linux

package main

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func workflowV4CloneDecisionInput(source, target string) (bool, error) {
	input, err := os.Open(source)
	if err != nil {
		return false, err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return false, err
	}
	cloneErr := unix.IoctlFileClone(int(output.Fd()), int(input.Fd()))
	closeErr := output.Close()
	if cloneErr == nil {
		return true, closeErr
	}
	if err := os.Remove(target); err != nil {
		return false, err
	}
	if errors.Is(cloneErr, syscall.ENOTSUP) || errors.Is(cloneErr, syscall.EOPNOTSUPP) || errors.Is(cloneErr, syscall.EXDEV) || errors.Is(cloneErr, syscall.ENOSYS) || errors.Is(cloneErr, syscall.EINVAL) {
		return false, nil
	}
	return false, cloneErr
}
