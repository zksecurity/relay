package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
)

var errSecretPromptInterrupted = errors.New("credential entry cancelled; terminal settings restored")

// Read from the controlling terminal, never a pipeline, shell argument, or
// the wizard's buffered public-input reader. stty receives settings, not secrets.
// Both supported hosts provide /bin/stty. No password-manager integration is
// required: the operator can paste from their preferred manager.
func promptProtectedSecret(out io.Writer, label string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", errors.New("hidden entry needs a controlling terminal; use an existing protected credential file instead")
	}
	defer tty.Close()
	settings := exec.Command("/bin/stty", "-g")
	settings.Stdin = tty
	state, err := settings.Output()
	if err != nil {
		return "", errors.New("cannot read terminal settings; no credential requested")
	}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(interrupts)
	restore := func() error {
		cmd := exec.Command("/bin/stty", strings.TrimSpace(string(state)))
		cmd.Stdin = tty
		return cmd.Run()
	}
	defer restore()
	hide := exec.Command("/bin/stty", "-echo")
	hide.Stdin = tty
	if err := hide.Run(); err != nil {
		return "", errors.New("cannot disable terminal echo; no credential requested")
	}
	fmt.Fprintf(out, "%s (hidden): ", label)
	type result struct {
		text string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		text, err := bufio.NewReader(io.LimitReader(tty, 16385)).ReadString('\n')
		done <- result{text, err}
	}()
	select {
	case <-interrupts:
		fmt.Fprintln(out)
		return "", errSecretPromptInterrupted
	case r := <-done:
		fmt.Fprintln(out)
		if err := restore(); err != nil {
			return "", errors.New("terminal restoration failed; run stty sane before continuing")
		}
		if r.err != nil || len(r.text) > 16384 {
			return "", errors.New("credential entry incomplete or too long")
		}
		value := strings.TrimSpace(r.text)
		if value == "" || strings.ContainsAny(value, " \t\r\n\x00") {
			return "", errors.New("enter a nonempty single-line credential without whitespace")
		}
		return value, nil
	}
}
