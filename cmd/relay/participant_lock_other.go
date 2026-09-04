//go:build !darwin && !linux

package main

import "errors"

type participantRunLock struct{}

func acquireParticipantRunLock(_, _ string) (*participantRunLock, error) {
	return nil, errors.New("participant runs are supported only on macOS and Linux")
}

func (l *participantRunLock) release() error { return nil }
