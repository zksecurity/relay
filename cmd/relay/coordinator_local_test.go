//go:build relaylocal

package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestLocalCoordinatorBoundaries(t *testing.T) {
	if coordinatorLocalRunner == nil {
		t.Fatal("local entry point not registered")
	}
	allowed := []string{"mpc-ceremony", "init", "--mode", "rehearsal", "--key-version", "rehearsal-tiny-v1"}
	if !localTestCommandAllowed("coordinator", allowed, false) {
		t.Fatal("tiny init rejected")
	}
	for _, command := range [][]string{
		{"relay", "coordinator", "configure-storage"},
		{"mpc-ceremony", "init", "--mode", "production", "--key-version", "ownership-destination-v2"},
		{"mpc-ceremony", "init", "--mode", "rehearsal", "--key-version", "ownership-destination-v2"},
		append(append([]string(nil), allowed...), "--allowed-binary", "extra"),
		{"mpc-ceremony", "phase1", "contribute"},
	} {
		if localTestCommandAllowed("coordinator", command, false) {
			t.Fatal("unsafe local command accepted", command)
		}
	}
	if localTestCommandAllowed("coordinator", allowed, true) {
		t.Fatal("local credentials accepted")
	}
	w := setupFixture(t)
	w.localAction = func(string, string, []string, bool) error { t.Fatal("local action executed"); return nil }
	w.input = bufio.NewReader(strings.NewReader("production\nownership-destination-v2\n"))
	if err := w.basics(); err == nil {
		t.Fatal("production mode accepted")
	}
	if err := w.configureStorage(); err == nil {
		t.Fatal("cloud action accepted")
	}
	w.d.Mode = "production"
	w.d.Circuit = "ownership-destination-v2"
	if err := w.initialize(); err == nil {
		t.Fatal("production init accepted")
	}
}
