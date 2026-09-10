package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

type terminalTone string

const (
	toneHeading terminalTone = "1"
	toneSuccess terminalTone = "32"
	toneWarning terminalTone = "33"
	toneError   terminalTone = "31"
	toneMuted   terminalTone = "2"
)

var terminalFiles sync.Map

// Only decorate human-facing wizard output. Never wrap machine-readable output
// or child processes. stty detects real terminals (unlike ModeCharDevice, which
// also matches /dev/null) on the supported Linux and macOS hosts.
func terminalColor(out io.Writer) bool {
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled {
		return false
	}
	if os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	file, ok := out.(*os.File)
	if !ok {
		return false
	}
	if cached, ok := terminalFiles.Load(file); ok {
		return cached.(bool)
	}
	cmd := exec.Command("/bin/stty", "-g")
	cmd.Stdin = file
	enabled := cmd.Run() == nil
	terminalFiles.Store(file, enabled)
	return enabled
}

func terminalText(out io.Writer, tone terminalTone, value string) string {
	if !terminalColor(out) {
		return value
	}
	return "\x1b[" + string(tone) + "m" + value + "\x1b[0m"
}

func (w *coordinatorWizard) message(tone terminalTone, format string, args ...any) {
	fmt.Fprint(w.output, terminalText(w.output, tone, fmt.Sprintf(format, args...)))
}
