//go:build !relaylocal

package main

import "testing"

func TestOrdinaryBuildHasNoLocalCoordinator(t *testing.T) {
	if coordinatorLocalRunner != nil {
		t.Fatal("local runner present in ordinary build")
	}
	if err := runCoordinator([]string{"prepare-local"}); err == nil {
		t.Fatal("ordinary build accepted local command")
	}
}
