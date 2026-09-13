package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorageBeforeInitializationRecommendsLocalNextStep(t *testing.T) {
	for _, state := range []string{"missing-settings", "missing-credentials", "configured", "unsafe-credentials", "missing-r2-control"} {
		t.Run(state, func(t *testing.T) {
			w := setupFixture(t)
			w.localAction = nil
			w.run = func([]string) error { t.Fatal("menu ran a command without approval"); return nil }
			w.d.Storage = storageSettingsFixture().Settings
			w.d.Credentials = filepath.Join(w.d.Keys, "test-aws")
			if err := os.WriteFile(w.d.Credentials, []byte("synthetic-test-credential"), 0600); err != nil {
				t.Fatal(err)
			}
			switch state {
			case "missing-settings":
				w.d.Storage = nil
			case "missing-credentials":
				w.d.Credentials += "-missing"
			case "unsafe-credentials":
				if err := os.Chmod(w.d.Credentials, 0644); err != nil {
					t.Fatal(err)
				}
			case "missing-r2-control":
				w.d.Storage = map[string]string{"provider": "r2", "region": "auto", "profile": "coordinator", "account-id": strings.Repeat("a", 32), "endpoint": "https://" + strings.Repeat("a", 32) + ".r2.cloudflarestorage.com", "parent-access-key-id": strings.Repeat("b", 32), "published-bucket": "published", "inbox-bucket": "inbox", "published-base-url": "https://public.example.test"}
				w.d.R2Parent = w.d.Credentials
				w.d.R2Control = ""
			}
			w.input = bufio.NewReader(strings.NewReader("0\n"))
			if err := w.prepareStorageBeforeInitialization(); err == nil {
				t.Fatal("cancel should stop initialization")
			}
			out := w.output.(*bytes.Buffer).String()
			want := "Choose a number [2]"
			if state == "configured" {
				want = "Choose a number [1]"
			}
			if !strings.Contains(out, want) || !strings.Contains(out, "[Recommended]") {
				t.Fatalf("wrong recommendation: %s", out)
			}
		})
	}
}
