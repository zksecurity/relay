package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestFocusEventsInWizardInput(t *testing.T) {
	for _, tc := range []struct{ input, fallback, want string }{
		{"\x1b[O\x1b[I1\x1b[O\n", "", "1"},
		{"REVI\x1b[IEWED\n", "", "REVIEWED"},
		{"\x1b[I\x1b[O\n", "default", "default"},
		{"^[[I\n", "", "^[[I"},
		{"\x1b[A\n", "", "\x1b[A"},
	} {
		w := setupFixture(t)
		w.input = bufio.NewReader(strings.NewReader(tc.input))
		got, err := w.ask("Answer", tc.fallback)
		if err != nil || got != tc.want {
			t.Fatalf("got %q, %v; want %q", got, err, tc.want)
		}
	}
}

func TestFocusDisableDoesNotWriteToLogs(t *testing.T) {
	var out bytes.Buffer
	disableTerminalFocusReporting(&out)
	if out.Len() != 0 {
		t.Fatal("terminal controls written to nonterminal output")
	}
}

func TestGuidedConfirmationIgnoresFocusWithoutConsumingNextAnswer(t *testing.T) {
	input := strings.NewReader("\x1b[O\x1b[Iy\x1b[O\nNEXT ANSWER\n")
	var out bytes.Buffer
	if err := confirmGuided(input, &out); err != nil {
		t.Fatal(err)
	}
	remaining := make([]byte, input.Len())
	_, _ = input.Read(remaining)
	if string(remaining) != "NEXT ANSWER\n" {
		t.Fatalf("consumed later input: %q", remaining)
	}
}

func TestBufferedFocusDoesNotDiscardPastedCredentials(t *testing.T) {
	for _, tc := range []struct{ input, remaining string }{
		{"\x1b[I\x1b[O", ""},
		{"\x1b[Isecret\n", "secret\n"},
		{"\x1b[", "\x1b["},
		{"\x1b[A", "\x1b[A"},
	} {
		r := bufio.NewReader(strings.NewReader(tc.input))
		_, _ = r.Peek(len(tc.input))
		discardBufferedFocusEvents(r)
		remaining, _ := r.Peek(r.Buffered())
		if string(remaining) != tc.remaining {
			t.Fatalf("got %q, want %q", remaining, tc.remaining)
		}
	}
}
