package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

// Only the three named public files are imported, never a directory tree that
// might also contain a signing key or a credential export.
func readEnrollmentPublicFile(root, name string) ([]byte, error) {
	if name == "" || filepath.IsAbs(name) || filepath.Clean(name) != name || name == ".." || strings.HasPrefix(name, "../") {
		return nil, errors.New("unsafe public enrollment file name")
	}
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, name)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("public enrollment files must not use symlinks")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("expected a regular public enrollment file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("public enrollment file exceeds its size limit")
	}
	return raw, nil
}

func importPublicEnrollment(source, destination string) error {
	record, err := readEnrollmentPublicFile(source, "canonical.json")
	if err != nil {
		return err
	}
	var projection struct {
		Disclosure transcript.ArtifactRef `json:"independence_disclosure"`
	}
	if err := json.Unmarshal(record, &projection); err != nil {
		return errors.New("invalid public enrollment JSON")
	}
	signature, err := readEnrollmentPublicFile(source, "enrollment.sig")
	if err != nil {
		return err
	}
	name := projection.Disclosure.Name
	if name == "canonical.json" || name == "enrollment.sig" {
		return errors.New("disclosure overlaps the signed record")
	}
	disclosure, err := readEnrollmentPublicFile(source, name)
	if err != nil {
		return err
	}
	if err := checkDisclosureBytes(projection.Disclosure, disclosure); err != nil {
		return err
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	for name, raw := range map[string][]byte{"canonical.json": record, "enrollment.sig": signature, name: disclosure} {
		path := filepath.Join(destination, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(raw)
		syncErr := file.Sync()
		closeErr := file.Close()
		if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
			return err
		}
	}
	return nil
}

func checkDisclosureBytes(ref transcript.ArtifactRef, raw []byte) error {
	hash := sha256.Sum256(raw)
	if ref.Digest.Size != int64(len(raw)) || ref.Digest.SHA256 != "sha256:"+hex.EncodeToString(hash[:]) {
		return errors.New("disclosure bytes do not match the signed reference")
	}
	return nil
}

func (f *roleFlow) collectedEnrollments() (bool, error) {
	i, binding, err := f.inspectionContext()
	if err != nil {
		return false, err
	}
	d, err := i.Definition()
	if err != nil {
		return false, err
	}
	requirements, err := d.RequireJourney()
	if err != nil {
		return false, err
	}
	root := filepath.Join(f.state.Profile.Work, "ceremony", "public", "collected-enrollments")
	dirs, err := os.ReadDir(root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	verified := map[string]transcript.EnrollmentInspection{}
	indices, keys := map[string]bool{}, map[string]bool{}
	attention := false
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		path := filepath.Join(root, dir.Name())
		record, err := readEnrollmentPublicFile(path, "canonical.json")
		if err != nil {
			attention = true
			fmt.Fprintf(f.ui.output, "Needs attention: %q is incomplete.\n", dir.Name())
			continue
		}
		sig, err := readEnrollmentPublicFile(path, "enrollment.sig")
		if err != nil {
			attention = true
			fmt.Fprintf(f.ui.output, "Received but unverified: %q has no readable signature.\n", dir.Name())
			continue
		}
		e, err := i.Enrollment(filepath.Join(path, "canonical.json"), filepath.Join(path, "enrollment.sig"))
		if err != nil {
			attention = true
			fmt.Fprintf(f.ui.output, "Needs attention: signature/binding verification failed for %q.\n", dir.Name())
			continue
		}
		after, recordErr := readEnrollmentPublicFile(path, "canonical.json")
		afterSig, sigErr := readEnrollmentPublicFile(path, "enrollment.sig")
		disclosure, disclosureErr := readEnrollmentPublicFile(path, e.IndependenceDisclosure.Name)
		if recordErr != nil || sigErr != nil || disclosureErr != nil || !bytes.Equal(record, after) || !bytes.Equal(sig, afterSig) || checkDisclosureBytes(e.IndependenceDisclosure, disclosure) != nil || e.CeremonyID != d.CeremonyID {
			attention = true
			fmt.Fprintf(f.ui.output, "Needs attention: changed files or invalid disclosure for %q.\n", dir.Name())
			continue
		}
		index := fmt.Sprintf("%s/%d", e.Role, e.RoleIndex)
		if _, exists := verified[e.Identity.ID]; exists || indices[index] || keys[e.Identity.KeyID] {
			return false, errors.New("conflicting or duplicate enrollment identity, key or role index; inspect the retained public records")
		}
		verified[e.Identity.ID], indices[index], keys[e.Identity.KeyID] = e, true, true
	}
	complete := !attention
	for _, expected := range requirements.RequiredEnrollments {
		e, ok := verified[expected.Identity.ID]
		status := "Missing"
		if ok {
			status = "Verified"
			if e.Role != expected.Role || e.RoleIndex != expected.RoleIndex || !reflect.DeepEqual(e.Identity, expected.Identity) {
				status = "Needs attention"
				ok = false
			}
		}
		complete = complete && ok
		fmt.Fprintf(f.ui.output, "%s — %s %q (%s)\n", status, expected.Role, expected.Identity.DisplayName, expected.Identity.ID)
	}
	counts := map[string]int{}
	for _, e := range verified {
		counts[e.Role]++
	}
	for role, minimum := range map[string]int{"public-witness": requirements.MinimumPublicWitnesses, "mirror-operator": requirements.MinimumMirrorsPerAcceptedHead} {
		fmt.Fprintf(f.ui.output, "%s enrollments: %d verified; verifier minimum %d. Confirm any higher agreed quorum separately.\n", role, counts[role], minimum)
		complete = complete && counts[role] >= minimum
	}
	if err := f.bindPublicInputs(binding); err != nil {
		return false, err
	}
	fmt.Fprintf(f.ui.output, "Rechecked now (%s) by approved proof-tool plus disclosure SHA-256/size checks. Distinct keys do not establish independent people. Enrollment does not complete witness or per-head mirror duties.\n", time.Now().UTC().Format(time.RFC3339))
	return complete, nil
}

func (f *roleFlow) collectEnrollment(task flowTask) error {
	if _, err := f.collectedEnrollments(); err != nil {
		fmt.Fprintf(f.ui.output, "Collection not verified: %v\nInspect or archive incorrect imports; no completion is recorded.\n", err)
	}
	choice, err := f.ui.choose("Enrollment collection", "", []setupChoice{{"import", "Import and verify one public enrollment folder"}, {"request", "Show what to request from each role"}, {"archive", "Inspect and archive an incorrect or duplicate import"}, {"cancel", "Return to ceremony actions"}})
	if err != nil {
		return err
	}
	if choice == "request" {
		fmt.Fprintln(f.ui.output, "Ask each role for its exported public enrollment folder: canonical.json, enrollment.sig, and the referenced public disclosure. Never request signing.hex, credentials or private grants. Request witness and mirror enrollments too; their identities are not part of the frozen participant roster.")
		return nil
	}
	if choice == "cancel" {
		return nil
	}
	if choice == "archive" {
		return f.archiveEnrollmentImport()
	}
	source, err := f.ui.required("Absolute path to the received PUBLIC enrollment folder", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(source) {
		return errors.New("use an absolute public folder path")
	}
	root := filepath.Join(f.state.Profile.Work, "ceremony", "public", "collected-enrollments")
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	if err := importPublicEnrollment(source, filepath.Join(root, id)); err != nil {
		return err
	}
	complete, err := f.collectedEnrollments()
	if err != nil {
		return err
	}
	status := "reviewed-incomplete"
	if complete {
		status = "succeeded"
	}
	f.state.Attempts = append(f.state.Attempts, flowAttempt{ID: id, Task: task.ID, Stage: f.stages[f.state.Stage].ID, Status: status, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano), Note: "Public enrollment collection checked; revalidation is required before leaving this stage."})
	return f.save()
}

func (f *roleFlow) archiveEnrollmentImport() error {
	root := filepath.Join(f.state.Profile.Work, "ceremony", "public", "collected-enrollments")
	dirs, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	choices := []setupChoice{}
	for _, dir := range dirs {
		if dir.IsDir() {
			choices = append(choices, setupChoice{dir.Name(), fmt.Sprintf("Import %q", dir.Name())})
		}
	}
	choices = append(choices, setupChoice{"cancel", "Return without changing files"})
	selected, err := f.ui.choose("Select the retained import to inspect; these labels are not verification results", "", choices)
	if err != nil || selected == "cancel" {
		return err
	}
	source := filepath.Join(root, selected)
	fmt.Fprintf(f.ui.output, "Selected public import: %s\n", source)
	if raw, err := readEnrollmentPublicFile(source, "canonical.json"); err == nil {
		var summary struct {
			Role     string                    `json:"role"`
			Identity transcript.PublicIdentity `json:"identity"`
		}
		if json.Unmarshal(raw, &summary) == nil {
			fmt.Fprintf(f.ui.output, "Unverified file label: %q, %q (%q). Archiving is not signature verification.\n", summary.Role, summary.Identity.DisplayName, summary.Identity.ID)
		}
	}
	if err := f.ui.confirm("Move this import out of the active collection, preserving all its public files in an archive. Its enrollment will no longer count until a valid replacement is imported", "ARCHIVE IMPORT"); err != nil {
		return err
	}
	archive := filepath.Join(f.state.Profile.Work, "ceremony", "public", "enrollment-import-archive")
	if err := ensurePrivateDirectory(archive); err != nil {
		return err
	}
	id, err := randomID()
	if err != nil {
		return err
	}
	destination := filepath.Join(archive, id)
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("archive destination is not fresh")
	}
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	fmt.Fprintf(f.ui.output, "Import archived at %s; no public files deleted. Re-import a corrected public enrollment through the collection menu.\n", destination)
	return nil
}
