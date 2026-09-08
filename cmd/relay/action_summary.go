package main

import (
	"fmt"
	"io"
	"strings"
)

// Show every argument as data, with host paths, without requiring shell literacy.
// This is presentation only: the exact saved command remains the executed action.
func writeActionSummary(out io.Writer, p guidedProfile, command []string) {
	end := 0
	for end < len(command) && !strings.HasPrefix(command[end], "--") {
		end++
	}
	fmt.Fprintf(out, "Saved operation: %s\n", strings.Join(command[:end], " → "))
	for n := end; n < len(command); n++ {
		arg := command[n]
		if strings.HasPrefix(arg, "--") {
			label := strings.ReplaceAll(strings.TrimPrefix(arg, "--"), "-", " ")
			if n+1 < len(command) && !strings.HasPrefix(command[n+1], "--") {
				n++
				fmt.Fprintf(out, "  %s: %s\n", label, flowHostPath(p, command[n]))
			} else {
				fmt.Fprintf(out, "  %s: enabled\n", label)
			}
		} else {
			fmt.Fprintf(out, "  argument: %s\n", flowHostPath(p, arg))
		}
	}
}

func (f *roleFlow) confirmAction(command []string) error {
	writeActionSummary(f.ui.output, f.state.Profile, command)
	for {
		answer, err := f.ui.ask("Review the inputs above. This may sign, publish or upload; type RUN to proceed, or DETAILS for the exact command", "")
		if err != nil {
			return err
		}
		if answer == "DETAILS" {
			fmt.Fprintf(f.ui.output, "Exact command: %q\n", command)
			continue
		}
		if answer != "RUN" {
			return fmt.Errorf("cancelled: no action was run")
		}
		return nil
	}
}
