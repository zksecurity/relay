package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
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

func TestOperationalRecordReviewRequiresHostDisconnectionOnlyForFinalSigner(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "release-signer"} {
		t.Run(role, func(t *testing.T) {
			root := t.TempDir()
			record := filepath.Join(root, "record.json")
			if err := os.WriteFile(record, []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			phrase := "REVIEWED"
			if role == "release-signer" {
				phrase = "OFFLINE AND REVIEWED"
			}
			var out bytes.Buffer
			f := roleFlow{state: roleFlowState{Role: role, Profile: guidedProfile{Work: root}}, ui: coordinatorWizard{input: bufio.NewReader(strings.NewReader(phrase + "\n")), output: &out}}
			if _, err := f.reviewOfflineRecord([]string{"mpc-ceremony", "ops", "sign", "--record", "/work/record.json"}); err != nil {
				t.Fatal(err)
			}
			if role == "release-signer" && !strings.Contains(out.String(), "Disconnect the signing host") {
				t.Fatal("final signer was not told to disconnect the host")
			}
			if role != "release-signer" && (!strings.Contains(out.String(), "network-disabled container") || strings.Contains(out.String(), "Disconnect the signing host")) {
				t.Fatalf("ordinary record misstated host disconnection: %s", out.String())
			}
		})
	}
}
