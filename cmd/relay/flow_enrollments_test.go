package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func TestEnrollmentCollectionLatestObservationSurvivesReload(t *testing.T) {
	f := flowFixture(t)
	task := flowTask{ID: "enrollment"}
	f.stages = []flowStage{{ID: "enrollments", Tasks: []flowTask{task}}}
	for _, result := range []bool{false, false, true} {
		if err := f.saveEnrollmentCheck(result, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !f.requiredTaskComplete(task) {
		t.Fatal("historical incomplete checks blocked latest complete collection")
	}
	var reloaded roleFlowState
	if err := setupReadJSON(f.path, &reloaded); err != nil {
		t.Fatal(err)
	}
	f.state = reloaded
	if !f.requiredTaskComplete(task) || len(f.state.Attempts) != 3 {
		t.Fatal("reload lost completion or history")
	}
	for _, checkErr := range []error{nil, errors.New("verification failed")} {
		if err := f.saveEnrollmentCheck(false, checkErr); err != nil {
			t.Fatal(err)
		}
		if f.requiredTaskComplete(task) {
			t.Fatal("later incomplete/failed check retained old success")
		}
	}
	count := len(f.state.Attempts)
	f.path = filepath.Join(f.path, "invalid-child")
	if err := f.saveEnrollmentCheck(true, nil); err == nil {
		t.Fatal("save failure ignored")
	}
	if len(f.state.Attempts) != count+1 || f.requiredTaskComplete(task) {
		t.Fatal("failed save exposed unpersisted success")
	}
	// Inverse case: failing to save a new failure must not resurrect old success.
	f.state.Attempts = f.state.Attempts[:3]
	if err := f.saveEnrollmentCheck(false, errors.New("changed signature")); err == nil {
		t.Fatal("save failure ignored")
	}
	if f.requiredTaskComplete(task) {
		t.Fatal("save failure resurrected previous success")
	}
}

func TestEnrollmentExceptionDoesNotHideUncertainOperations(t *testing.T) {
	for _, tc := range []struct{ role, stage, task string }{
		{"coordinator", "phase1-turns", "sign"},
		{"participant", "phase1", "contribute"},
		{"participant", "phase1", "upload"},
		{"participant", "enrollments", "enrollment"},
		{"coordinator", "other", "enrollment"},
	} {
		t.Run(tc.role+"/"+tc.stage+"/"+tc.task, func(t *testing.T) {
			f := flowFixture(t)
			f.state.Role = tc.role
			f.stages[0].ID = tc.stage
			f.state.Attempts = []flowAttempt{
				{ID: "old", Task: tc.task, Stage: tc.stage, Status: "running"},
				{ID: "new", Task: tc.task, Stage: tc.stage, Status: "succeeded"},
			}
			if f.last(flowTask{ID: tc.task}).ID != "old" {
				t.Fatal("uncertain operation suppressed")
			}
		})
	}
}

// Uses real signed public inputs, copied into a disposable workspace. Never
// modifies the supplied ceremony or invokes signing/cloud commands.
func TestDockerEnrollmentHistoryRecovery(t *testing.T) {
	source := os.Getenv("RELAY_COLLECTION_TEST_WORK")
	if source == "" {
		t.Skip("requires explicit public enrollment collection fixture and Docker")
	}
	f := flowFixture(t)
	work := privateRoleTestDir(t)
	root := filepath.Join(work, "ceremony/public")
	if err := os.MkdirAll(filepath.Join(root, "collected-enrollments"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ceremony.json", "ceremony.sig", "coordinator-public-key.hex"} {
		raw, err := readPreparationInput(filepath.Join(source, "ceremony/public", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.state.Profile = guidedProfile{Work: work, Trust: root, Image: os.Getenv("RELAY_ROLE_ONLINE_IMAGE"), Platform: "linux/arm64"}
	task := flowTask{ID: "enrollment"}
	f.stages = []flowStage{{ID: "enrollments", Tasks: []flowTask{task}}}
	if complete, err := f.recordEnrollmentCheck(); err != nil || complete {
		t.Fatalf("empty collection: %v %v", complete, err)
	}
	dirs, err := os.ReadDir(filepath.Join(source, "ceremony/public/collected-enrollments"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range dirs {
		if dir.IsDir() {
			if err := importPublicEnrollment(filepath.Join(source, "ceremony/public/collected-enrollments", dir.Name()), filepath.Join(root, "collected-enrollments", dir.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.ui.input = bufio.NewReader(strings.NewReader("0\n"))
	if err := f.collectEnrollment(task); err != nil {
		t.Fatal(err)
	}
	if !f.requiredTaskComplete(task) {
		t.Fatal("return after authenticated complete check did not unblock guide")
	}
	if err := setupReadJSON(f.path, &f.state); err != nil || !f.requiredTaskComplete(task) {
		t.Fatal("completion lost on reload", err)
	}
	// Archive through the real submenu, then check the recommendation is blocked.
	f.ui.input = bufio.NewReader(strings.NewReader("3\n1\nARCHIVE IMPORT\n"))
	if err := f.collectEnrollment(task); err != nil {
		t.Fatal(err)
	}
	if f.requiredTaskComplete(task) {
		t.Fatal("archive left stale success")
	}
	if err := f.advance(); err == nil || f.requiredTaskComplete(task) {
		t.Fatal("incomplete collection advanced")
	}
}

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
