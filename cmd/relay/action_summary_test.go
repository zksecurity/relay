package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestActionSummaryPreservesConsentAndArguments(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = "/local/work"
	command := []string{"mpc-ceremony", "inspect", "definition", "--ceremony", "/work/definition.json", "--verify"}
	f.ui.input = bufio.NewReader(strings.NewReader("DETAILS\nRUN\n"))
	if err := f.confirmAction(command); err != nil {
		t.Fatal(err)
	}
	out := f.ui.output.(*bytes.Buffer).String()
	for _, text := range []string{"/local/work/definition.json", "verify: enabled", "Exact command:", "/work/definition.json"} {
		if !strings.Contains(out, text) {
			t.Fatalf("missing %q in %s", text, out)
		}
	}
	f.ui.input = bufio.NewReader(strings.NewReader("DETAILS\nno\n"))
	if err := f.confirmAction(command); err == nil {
		t.Fatal("viewing details authorized execution")
	}
	if command[4] != "/work/definition.json" {
		t.Fatal("display changed command")
	}
}
