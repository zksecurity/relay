package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMacVerifierDockerArgs(t *testing.T) {
	for _, platform := range []string{"linux/arm64", "linux/amd64"} {
		args := macVerifierDockerArgs(platform, "image@sha256:trusted", "/public/archive.zip", "", "/private/scratch", "", "", 1024)
		joined := strings.Join(args, " ")
		for _, required := range []string{"--platform " + platform, "--network none", "--read-only", "--cap-drop ALL", "no-new-privileges", "source=/public/archive.zip,target=/work/archive.zip,readonly", "source=/private/scratch,target=/scratch", "--max-expanded-bytes 1024", "--mpc-ceremony /usr/local/bin/mpc-ceremony"} {
			if !strings.Contains(joined, required) {
				t.Fatalf("missing %q from %q", required, joined)
			}
		}
		if strings.Contains(joined, "coordinator-key.hex") {
			t.Fatal("archive-only verification mounted a coordinator key")
		}
	}
	args := macVerifierDockerArgs("linux/arm64", "image@sha256:trusted", "/public/archive.zip", "/trusted/coordinator.hex", "/private/scratch", "https://public.example", "sha256:expected", 2048)
	joined := strings.Join(args, " ")
	for _, required := range []string{"--published-base-url https://public.example", "--expected-ceremony-id sha256:expected", "source=/trusted/coordinator.hex,target=/work/coordinator-key.hex,readonly"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing %q from %q", required, joined)
		}
	}
	if strings.Contains(joined, "--network none") {
		t.Fatal("publication check disabled network")
	}
	if !reflect.DeepEqual(args[len(args)-6:], []string{"--published-base-url", "https://public.example", "--expected-ceremony-id", "sha256:expected", "--expected-coordinator-public-key-file", "/work/coordinator-key.hex"}) {
		t.Fatalf("publication arguments: %v", args)
	}
}

func TestMacVerifierRegularPathRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "archive.zip")
	if err := os.WriteFile(file, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := macVerifierRegularPath(file); err != nil || got != file {
		t.Fatalf("regular file: %q %v", got, err)
	}
	link := filepath.Join(dir, "archive-link.zip")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := macVerifierRegularPath(link); err == nil {
		t.Fatal("symlink accepted")
	}
}
