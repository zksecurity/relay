package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestWizardPlainOutput(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	var out bytes.Buffer
	w := coordinatorWizard{output: &out}
	w.message(toneError, "Stopped: %s\n", "inspect retained output")
	if got := out.String(); got != "Stopped: inspect retained output\n" {
		t.Fatalf("plain output changed: %q", got)
	}
}

func TestTerminalStylePolicy(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if terminalColor(file) {
		t.Fatal("redirected output received color")
	}
	// Exercise decoration and environment overrides independently of the host TTY.
	terminalFiles.Store(file, true)
	defer terminalFiles.Delete(file)
	old, present := os.LookupEnv("NO_COLOR")
	os.Unsetenv("NO_COLOR")
	defer func() {
		if present {
			os.Setenv("NO_COLOR", old)
		} else {
			os.Unsetenv("NO_COLOR")
		}
	}()
	if got := terminalText(file, toneSuccess, "Verified"); got != "\x1b[32mVerified\x1b[0m" {
		t.Fatalf("missing style/reset: %q", got)
	}
	t.Setenv("NO_COLOR", "")
	if terminalColor(file) {
		t.Fatal("NO_COLOR presence must disable styling")
	}
	os.Unsetenv("NO_COLOR")
	t.Setenv("TERM", "dumb")
	if terminalColor(file) {
		t.Fatal("dumb terminal received color")
	}
}

func TestTerminalStylePTY(t *testing.T) {
	if os.Getenv("RELAY_STYLE_PTY_TEST") != "1" {
		t.Skip("run in a real PTY for terminal detection")
	}
	if !terminalColor(os.Stdout) {
		t.Fatal("PTY not recognized")
	}
	value := terminalText(os.Stdout, toneHeading, "Ceremony setup")
	if !strings.Contains(value, "\x1b[1m") {
		t.Fatal("heading missing")
	}
	t.Log(value)
}
