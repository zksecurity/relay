package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestHiddenCredentialPromptProcess(t *testing.T) {
	mode := os.Getenv("RELAY_SECRET_PROMPT_TEST")
	if mode == "" {
		return
	}
	state := func() []byte {
		cmd := exec.Command("/bin/stty", "-g")
		cmd.Stdin = os.Stdin
		raw, err := cmd.Output()
		if err != nil {
			t.Fatal("terminal unavailable")
		}
		return raw
	}
	before := state()
	value, err := promptProtectedSecret(os.Stdout, "TEST credential")
	if mode == "normal" {
		if err != nil || value != "FAKE_SECRET_MUST_NOT_ECHO" {
			t.Fatal("hidden entry failed")
		}
	} else if !errors.Is(err, errSecretPromptInterrupted) {
		t.Fatal("interrupt was not handled")
	}
	if !bytes.Equal(before, state()) {
		t.Fatal("terminal settings were not restored")
	}
	_, _ = os.Stdout.WriteString("RESTORED_AND_CHECKED\n")
}

func TestHiddenCredentialPromptPTY(t *testing.T) {
	expect, err := exec.LookPath("expect")
	if err != nil {
		t.Skip("expect is required for real-terminal tests")
	}
	for _, mode := range []string{"normal", "interrupt"} {
		t.Run(mode, func(t *testing.T) {
			script := `set timeout 10
spawn -noecho $env(RELAY_PROMPT_TEST_BINARY) -test.run=^TestHiddenCredentialPromptProcess$ -test.v
expect "TEST credential (hidden): "
if {$env(RELAY_SECRET_PROMPT_TEST) eq "normal"} {
 send -- "FAKE_SECRET_MUST_NOT_ECHO\r"
} else {
 send -- "\003"
}
expect {
 "RESTORED_AND_CHECKED" {}
 timeout { exit 90 }
 eof { exit 91 }
}
expect eof
set status [wait]
exit [lindex $status 3]
`
			cmd := exec.Command(expect, "-c", script)
			cmd.Env = append(os.Environ(), "RELAY_PROMPT_TEST_BINARY="+os.Args[0], "RELAY_SECRET_PROMPT_TEST="+mode)
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("terminal test failed: %v\n%s", err, raw)
			}
			if strings.Contains(string(raw), "FAKE_SECRET_MUST_NOT_ECHO") {
				t.Fatal("terminal echoed credential")
			}
		})
	}
}
