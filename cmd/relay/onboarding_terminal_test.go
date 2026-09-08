package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// A real PTY checks the launcher -> child Docker confirmation boundary. Feeding
// all answers through a pipe would not model a user waiting for each prompt.
func testOfflineReceiptTerminal(t *testing.T, p *rolePreparer, online, offline, platform string) {
	t.Helper()
	binary := os.Getenv("RELAY_NATIVE_TEST_BINARY")
	if binary == "" {
		t.Log("PTY lane not requested: set RELAY_NATIVE_TEST_BINARY to a freshly built local launcher")
		return
	}
	expect, err := exec.LookPath("expect")
	if err != nil {
		t.Fatal("PTY lane requires expect", err)
	}
	settings := filepath.Join(p.d.Work, "terminal-settings")
	name := "terminal-" + p.d.Role
	for _, role := range []string{p.d.Role, "decision-signer"} {
		alias, image, keys := name, online, ""
		if role == "decision-signer" {
			alias, image, keys = offlineRoleAlias(name, p.d.Role), offline, p.d.Keys
		}
		dir, err := guidedDirectory(settings, alias, role)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		profile := guidedProfile{Schema: guidedSchema, Name: alias, Role: role, Image: image, Platform: platform, Work: p.d.Work, Trust: p.d.Trust, Keys: keys}
		if err := writeJSONNoReplace(filepath.Join(dir, "profile.json"), profile, 0600); err != nil {
			t.Fatal(err)
		}
	}
	signNumber := "3"
	if p.d.Role == "mirror" {
		signNumber = "4"
	}
	script := `set timeout 45
proc reply {value} {
 expect {
  -re {(\]: |: |\] )$} { send -- "$value\r" }
  timeout { puts stderr "Timed out waiting for a prompt"; exit 90 }
  eof { puts stderr "Unexpected end before prompt"; exit 91 }
 }
}
spawn -noecho $env(RELAY_TERMINAL_BINARY) ceremony guide $env(RELAY_TERMINAL_NAME) --role $env(RELAY_TERMINAL_ROLE) --settings-root $env(RELAY_TERMINAL_SETTINGS)
reply 1
reply 1
reply 2
for {set i 0} {$i < 5} {incr i} {reply {}}
reply RUN
reply y
expect {
 -exact {Command completed.} {}
 timeout {exit 92}
 eof {exit 93}
}
reply 3
reply CONTINUE
reply ` + signNumber + `
for {set i 0} {$i < 7} {incr i} {reply {}}
reply RUN
reply {OFFLINE AND REVIEWED}
reply y
expect {
 -exact {Command completed.} {}
 timeout {exit 94}
 eof {exit 95}
}
reply 0
expect {
 eof {}
 timeout {exit 96}
}
set result [wait]
if {[lindex $result 2] != 0 || [llength $result] > 4} {exit 97}
exit [lindex $result 3]
`
	command := exec.Command(expect, "-c", script)
	command.Env = append(os.Environ(), "RELAY_TERMINAL_BINARY="+binary, "RELAY_TERMINAL_NAME="+name, "RELAY_TERMINAL_ROLE="+p.d.Role, "RELAY_TERMINAL_SETTINGS="+settings)
	var trace bytes.Buffer
	command.Stdout = io.MultiWriter(&trace, os.Stdout)
	command.Stderr = io.MultiWriter(&trace, os.Stderr)
	if err := command.Run(); err != nil {
		t.Fatalf("actual %s terminal workflow: %v\n%s", p.d.Role, err, trace.String())
	}
	if _, err := os.Stat(filepath.Join(p.d.Work, "phase1-receipt/receipt-2.sig")); err != nil {
		t.Fatal("terminal did not create a fresh signature", err)
	}
	t.Log(fmt.Sprintf("%s actual terminal and child-Docker signing passed (%s)", p.d.Role, strconv.Quote(name)))
}
