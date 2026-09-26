//go:build darwin

package main

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func workflowV4CloneDecisionInput(source, target string) (bool, error) {
	if err := unix.Clonefile(source, target, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.ENOSYS) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
