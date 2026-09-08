package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsumeR2Credential(t *testing.T) {
	name := r2ControlTokenEnvironment
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("test-only-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(name, "")
	t.Setenv(name+"_FILE", path)
	got, err := consumeR2Credential(name)
	if err != nil || got != "test-only-token" {
		t.Fatalf("read: %q %v", got, err)
	}
	if os.Getenv(name+"_FILE") != "" {
		t.Fatal("credential reference inherited")
	}
	t.Setenv(name, "test-only-token")
	t.Setenv(name+"_FILE", path)
	if _, err := consumeR2Credential(name); err == nil {
		t.Fatal("accepted ambiguous sources")
	}
	if os.Getenv(name) != "" || os.Getenv(name+"_FILE") != "" {
		t.Fatal("ambiguity left credential in environment")
	}
	for _, raw := range []string{"", "two\nvalues", strings.Repeat("x", 16385)} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readProtectedCredential(path); err == nil {
			t.Fatal("accepted malformed credential")
		}
	}
	if err := os.WriteFile(path, []byte("test-only-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedCredential(path); err == nil {
		t.Fatal("accepted public file")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtectedCredential(link); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestR2CredentialMountsAreTaskScoped(t *testing.T) {
	dir := t.TempDir()
	work, trust := filepath.Join(dir, "work"), filepath.Join(dir, "trust")
	for _, p := range []string{work, trust} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	parent, control := filepath.Join(dir, "parent"), filepath.Join(dir, "control")
	for _, p := range []string{parent, control} {
		if err := os.WriteFile(p, []byte("test-only-secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	o := dockerRoleOptions{role: "coordinator", image: "sha256:" + strings.Repeat("a", 64), platform: "linux/arm64", work: work, trust: trust, r2Parent: parent, r2Control: control}
	for _, tc := range []struct {
		command         []string
		parent, control bool
	}{
		{[]string{"relay", "coordinator", "grant"}, true, false},
		{[]string{"relay", "coordinator", "configure-storage"}, true, true},
		{[]string{"relay", "coordinator", "check-storage"}, true, true},
		{[]string{"mpc-ceremony", "inspect", "definition"}, false, false},
		{[]string{"aws", "s3api", "head-bucket"}, false, false},
	} {
		args, err := dockerRoleArgs(o, tc.command, 501, 20)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "test-only-secret") {
			t.Fatal("secret leaked to argv")
		}
		if strings.Contains(joined, "dst=/credentials/r2-parent,readonly") != tc.parent || strings.Contains(joined, "dst=/credentials/r2-control,readonly") != tc.control {
			t.Fatal("incorrect mounts", joined)
		}
	}
	o.role = "auditor"
	if _, err := dockerRoleArgs(o, []string{"relay", "auditor", "run"}, 501, 20); err == nil {
		t.Fatal("noncoordinator received admin credential")
	}
}
