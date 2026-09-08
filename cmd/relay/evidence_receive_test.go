package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func TestReceiveEvidenceFreshScopedAndHashChecked(t *testing.T) {
	for _, fault := range []string{"", "wrong-ceremony", "wrong-role", "wrong-key", "changed-bytes", "existing-output"} {
		t.Run(fault, func(t *testing.T) {
			root := privateRoleTestDir(t)
			source := filepath.Join(root, "source")
			if err := os.WriteFile(source, []byte("signed fixture bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			ref, err := regularFileRef(source, "manifest.json")
			if err != nil {
				t.Fatal(err)
			}
			ceremony := "sha256:" + strings.Repeat("a", 64)
			id, err := randomID()
			if err != nil {
				t.Fatal(err)
			}
			m := access.SubmissionManifest{Schema: access.SubmissionManifestSchema, CeremonyID: ceremony, Role: "release", IdentityID: "signer", AttemptID: id, CompletedAt: time.Now().UTC().Format(time.RFC3339), Files: []access.FileRef{ref}}
			prefix, _ := access.Prefix(ceremony, m.Role, m.IdentityID)
			key := prefix + id + "/manifest.json"
			role := "release"
			out := filepath.Join(root, "received")
			switch fault {
			case "wrong-ceremony":
				m.CeremonyID = "sha256:" + strings.Repeat("b", 64)
			case "wrong-role":
				role = "auditor"
			case "wrong-key":
				key += "wrong"
			case "existing-output":
				if err := os.Mkdir(out, 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			err = receiveEvidence(ceremony, role, key, out, m, func(key, path string, size int64) error {
				if !strings.HasSuffix(key, "/files/manifest.json") {
					t.Fatal("payload manifest collided with transport manifest", key)
				}
				calls++
				data := []byte("signed fixture bytes")
				if fault == "changed-bytes" {
					data = []byte("changed")
				}
				return os.WriteFile(path, data, 0600)
			})
			if (err == nil) != (fault == "") {
				t.Fatal(fault, err)
			}
			if strings.HasPrefix(fault, "wrong-") && calls != 0 {
				t.Fatal("download started before scope check")
			}
			if fault == "changed-bytes" {
				if _, err := os.Stat(out + ".receipt.json"); !os.IsNotExist(err) {
					t.Fatal("partial output marked complete")
				}
			}
			if fault == "" {
				entries, err := os.ReadDir(out)
				if err != nil || len(entries) != 1 || entries[0].Name() != "manifest.json" {
					t.Fatal("transport metadata changed release tree", err)
				}
			}
		})
	}
}
