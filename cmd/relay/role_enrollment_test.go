package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestEnrollmentReviewPolicy(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer"} {
		t.Run(role, func(t *testing.T) {
			phrase := "REVIEWED"
			if role == "release-signer" {
				phrase = "OFFLINE AND REVIEWED"
			}
			var out bytes.Buffer
			p := rolePreparer{d: rolePreparation{Role: role}, ui: coordinatorWizard{input: bufio.NewReader(strings.NewReader(phrase + "\n")), output: &out}}
			if err := p.reviewEnrollment(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "network-disabled container") {
				t.Fatal("container protection not explained")
			}
			if role != "release-signer" && (!strings.Contains(out.String(), "does not claim the host is offline") || strings.Contains(out.String(), "OFFLINE AND REVIEWED")) {
				t.Fatal("ordinary enrollment misstates host disconnection")
			}
			p.ui.input = bufio.NewReader(strings.NewReader("\n"))
			if err := p.reviewEnrollment(); err == nil {
				t.Fatal("blank confirmation accepted")
			}
			if role == "release-signer" {
				p.ui.input = bufio.NewReader(strings.NewReader("REVIEWED\n"))
				if err := p.reviewEnrollment(); err == nil {
					t.Fatal("final signer bypassed offline confirmation")
				}
			}
		})
	}
}
