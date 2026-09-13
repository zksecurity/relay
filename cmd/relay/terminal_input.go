package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// A buffered menu reader may have read ahead across the newline. Remove only
// complete focus events before the existing anti-multipaste secret guard.
func discardBufferedFocusEvents(input *bufio.Reader) {
	for input.Buffered() >= 3 {
		prefix, _ := input.Peek(3)
		if string(prefix) != "\x1b[I" && string(prefix) != "\x1b[O" {
			return
		}
		_, _ = input.Discard(3)
	}
}

// Only remove actual focus-in/out events. Literal text such as "^[[I",
// arrow keys, and other escape sequences are not focus notifications.
func withoutTerminalFocusEvents(value string) string {
	return strings.NewReplacer("\x1b[I", "", "\x1b[O", "").Replace(value)
}

// Line-oriented prompts do not consume focus events. Disable reporting before
// input so the terminal does not echo them; also filter already queued events.
// Do not force-enable reporting on exit: the next TUI owns its terminal modes.
func disableTerminalFocusReporting(out io.Writer) {
	file, ok := out.(*os.File)
	if !ok {
		return
	}
	cmd := exec.Command("/bin/stty", "-g")
	cmd.Stdin = file
	if cmd.Run() == nil {
		fmt.Fprint(file, "\x1b[?1004l")
	}
}
