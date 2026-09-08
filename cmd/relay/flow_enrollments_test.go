package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func enrollmentImportFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	data := []byte("I operate all rehearsal roles on one machine.\n")
	hash := sha256.Sum256(data)
	ref := transcript.ArtifactRef{Name: "enrollments/test/disclosure.txt", Digest: transcript.Digest{SHA256: "sha256:" + hex.EncodeToString(hash[:]), Size: int64(len(data))}}
	raw, err := json.Marshal(map[string]any{"independence_disclosure": ref})
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"canonical.json": raw, "enrollment.sig": []byte("test signature, not cryptographically verified by import"), ref.Name: data, "signing.hex": []byte("must never be copied")} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(t.TempDir(), "received")
}

func TestEnrollmentArchivePreservesIncorrectPublicImport(t *testing.T) {
	f := flowFixture(t)
	f.state.Profile.Work = t.TempDir()
	root := filepath.Join(f.state.Profile.Work, "ceremony/public/collected-enrollments")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	source, _ := enrollmentImportFixture(t)
	if err := importPublicEnrollment(source, filepath.Join(root, "incorrect")); err != nil {
		t.Fatal(err)
	}
	f.ui.input = bufio.NewReader(strings.NewReader("1\nARCHIVE IMPORT\n"))
	if err := f.archiveEnrollmentImport(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "incorrect")); !os.IsNotExist(err) {
		t.Fatal("import still active")
	}
	archive := filepath.Join(f.state.Profile.Work, "ceremony/public/enrollment-import-archive")
	dirs, err := os.ReadDir(archive)
	if err != nil || len(dirs) != 1 {
		t.Fatal("archive missing", err)
	}
	if _, err := os.Stat(filepath.Join(archive, dirs[0].Name(), "canonical.json")); err != nil {
		t.Fatal("public record was lost")
	}
}

func TestEnrollmentImportCopiesOnlyNamedPublicFiles(t *testing.T) {
	source, dest := enrollmentImportFixture(t)
	if err := importPublicEnrollment(source, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "signing.hex")); !os.IsNotExist(err) {
		t.Fatal("private file was copied")
	}
	if err := importPublicEnrollment(source, dest); err == nil {
		t.Fatal("existing import overwritten")
	}
}

func TestEnrollmentImportRejectsChangedDisclosureAndSymlinks(t *testing.T) {
	for _, kind := range []string{"changed", "symlink", "ancestor-symlink"} {
		t.Run(kind, func(t *testing.T) {
			source, dest := enrollmentImportFixture(t)
			path := filepath.Join(source, "enrollments/test/disclosure.txt")
			switch kind {
			case "changed":
				if err := os.WriteFile(path, []byte("different claim"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "ancestor-symlink":
				dir := filepath.Dir(path)
				if err := os.Rename(dir, dir+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-original", dir); err != nil {
					t.Fatal(err)
				}
			}
			if err := importPublicEnrollment(source, dest); err == nil {
				t.Fatal("unsafe import accepted")
			}
		})
	}
}

func TestEnrollmentPublicPathRejectsTraversal(t *testing.T) {
	for _, name := range []string{"", "../signing.hex", "/signing.hex", "a/../../signing.hex"} {
		if _, err := readEnrollmentPublicFile(t.TempDir(), name); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}
