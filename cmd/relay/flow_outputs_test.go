package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreshOutputsPreserveExistingFiles(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	path := filepath.Join(f.state.Profile.Work, "audit.json")
	if err := os.WriteFile(path, []byte("signed output"), 0600); err != nil {
		t.Fatal(err)
	}
	next, err := f.freshOutputDefault("/work/audit.json")
	if err != nil || next != "/work/audit-2.json" {
		t.Fatalf("%s %v", next, err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "signed output" {
		t.Fatal("existing output changed")
	}
	if _, err := os.Stat(filepath.Join(f.state.Profile.Work, "audit-2.json")); !os.IsNotExist(err) {
		t.Fatal("allocated before approval")
	}
	task := flowTask{Fields: []flowField{ff("out", "Fresh audit", "/work/audit.json")}}
	f.rememberSuccessfulOutputs(task, []string{"tool", "--out", next})
	if f.state.Values["output//work/audit.json"] != next {
		t.Fatal("forgot successful artifact")
	}
	if flowIndependentOutput(task, ff("out-dir", "Phase 2", "/work/ceremony/public/phase2")) {
		t.Fatal("silently moved protocol directory")
	}
}

func TestFreshReceiptDirectoryPropagatesToSigningAndUpload(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	if err := os.Mkdir(filepath.Join(f.state.Profile.Work, "phase1-receipt"), 0700); err != nil {
		t.Fatal(err)
	}
	task := flowProof("receipt", "Receipt", "Public observation", "ops", "prepare-public-witness-receipt")
	task.Fields = append(task.Fields, ff("out-dir", "Fresh receipt export", "/work/phase1-receipt"))
	if !flowIndependentOutput(task, task.Fields[len(task.Fields)-1]) {
		t.Fatal("receipt exports should get fresh directories")
	}
	next, err := f.freshOutputDefault("/work/phase1-receipt")
	if err != nil || next != "/work/phase1-receipt-2" {
		t.Fatal(next, err)
	}
	f.rememberSuccessfulOutputs(task, []string{"mpc-ceremony", "ops", "prepare-public-witness-receipt", "--out-dir", next})
	for input, want := range map[string]string{"/work/phase1-receipt": next, "/work/phase1-receipt/canonical.json": next + "/canonical.json", "/work/phase1-receipt/receipt.sig": next + "/receipt.sig", "/work/phase1-receipt-other": "/work/phase1-receipt-other"} {
		if got := f.rememberedOutputPath(input, true); got != want {
			t.Fatalf("%s: %s != %s", input, got, want)
		}
	}
}
