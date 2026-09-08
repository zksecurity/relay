package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func offlineRoleAlias(name, role string) string {
	return fmt.Sprintf("offline-%x", sha256.Sum256([]byte(name+"\x00"+role)))[:40]
}

func (w *coordinatorWizard) enrollCoordinator() error {
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	// The independently established coordinator key already used during setup
	// is the trust anchor, not a key taken from a newly imported definition.
	raw, err := readPreparationInput(filepath.Join(w.d.Trust, "setup-coordinator.hex"))
	if err != nil {
		return err
	}
	if err := writePublicTextOnce(filepath.Join(w.d.Trust, "coordinator-public-key.hex"), string(raw)); err != nil {
		return err
	}
	p := &rolePreparer{d: rolePreparation{Schema: "relay-role-preparation-v1", Name: w.d.Name, Role: "coordinator", Release: w.d.Release, Work: w.d.Work, Trust: w.d.Trust, Keys: w.d.Keys, Values: map[string]string{}}, path: filepath.Join(w.d.Work, "coordinator-setup", "enrollment-draft.json"), settingsRoot: root, ui: *w, run: w.run}
	if err := p.setup("decision-signer"); err != nil {
		return err
	}
	return p.enroll()
}

func (p *rolePreparer) enroll() error {
	if p.d.Role == "upload-station" {
		return errors.New("an upload station has no signing identity; import the final signer's enrollment instead")
	}
	if _, err := p.profile("decision-signer"); err != nil {
		return fmt.Errorf("prepare approved images first, including the offline signing image: %w", err)
	}
	var identity setupIdentity
	if err := setupReadJSON(filepath.Join(p.d.Keys, "identity.json"), &identity); err != nil {
		return err
	}
	if err := identity.check(); err != nil {
		return err
	}
	role := p.d.Role
	if role == "witness" {
		role = "public-witness"
	}
	if role == "mirror" {
		role = "mirror-operator"
	}
	index := "1"
	var err error
	if role == "public-witness" || role == "mirror-operator" {
		index, err = p.value("enrollment-index", "Your one-based enrollment number supplied by the coordinator", "")
		if err != nil {
			return err
		}
		if err := validateFlowValue(flowField{Kind: "number"}, index); err != nil {
			return err
		}
	}
	dir := filepath.Join(p.d.Work, "my-enrollment")
	record := filepath.Join(dir, "canonical.json")
	if _, err := os.Lstat(record); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(p.ui.output, "For a same-machine rehearsal, an example disclosure is: 'I operate all ceremony roles on the same Mac.' Use that only if true; otherwise describe your actual shared people, organization or equipment.")
		text, err := p.ui.required("Public disclosure: describe who operates this role and any shared people, organizations or machines (do not include secrets)", "")
		if err != nil {
			return err
		}
		if err := p.ui.confirm("This statement will be public. Software checks distinct keys, not independent people", "PUBLIC DISCLOSURE"); err != nil {
			return err
		}
		disclosure := filepath.Join(p.d.Work, "enrollment-disclosure.txt")
		if err := writePublicTextOnce(disclosure, text+"\n"); err != nil {
			return err
		}
		args := []string{"mpc-ceremony", "ops", "prepare-enrollment", "--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/coordinator-public-key.hex", "--identity", "/keys/identity.json", "--role", role, "--role-index", index, "--disclosure", "/work/enrollment-disclosure.txt", "--enrolled-at", time.Now().UTC().Format(time.RFC3339Nano), "--out-dir", "/work/my-enrollment"}
		if err := p.open("decision-signer", "prepare-enrollment", args); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	// Always show the exact public bytes, including on resume. Never infer consent
	// from a previously completed preparation task or a coordinator's signature.
	raw, err := readPreparationInput(record)
	if err != nil {
		return err
	}
	var summary struct {
		CeremonyID string        `json:"ceremony_id"`
		Identity   setupIdentity `json:"identity"`
		Role       string        `json:"role"`
		RoleIndex  int           `json:"role_index"`
		EnrolledAt string        `json:"enrolled_at"`
	}
	if err := json.Unmarshal(raw, &summary); err != nil {
		return errors.New("cannot summarize enrollment record; preserve it and investigate")
	}
	if summary.Identity != identity || summary.Role != role || summary.RoleIndex < 1 {
		return errors.New("enrollment record differs from your selected identity or role; do not sign")
	}
	fmt.Fprintf(p.ui.output, "\nYOUR PUBLIC ENROLLMENT\n------------------------------------------------------------\nName: %q\nIdentity: %s\nRole: %s (assignment %d)\nCeremony: %s\nRecorded time: %s\nPublic key fingerprint: %s\n", summary.Identity.DisplayName, summary.Identity.ID, summary.Role, summary.RoleIndex, summary.CeremonyID, summary.EnrolledAt, summary.Identity.Fingerprint)
	disclosure, err := readPreparationInput(filepath.Join(dir, "enrollments", identity.ID, "disclosure.txt"))
	if err != nil {
		return err
	}
	fmt.Fprintf(p.ui.output, "Your public independence disclosure (control characters escaped):\n%q\n", disclosure)
	// The record hash below is the same binding later passed to proof-tool.
	// DETAILS never substitutes for signing consent.
	fmt.Fprintf(p.ui.output, "Exact record SHA-256: %x\n", sha256.Sum256(raw))
	if err := p.reviewEnrollmentDetails(raw); err != nil {
		return err
	}
	sig := filepath.Join(dir, "enrollment.sig")
	if _, err := os.Lstat(sig); errors.Is(err, os.ErrNotExist) {
		args := []string{"mpc-ceremony", "ops", "sign", "--record-type", "enrollment", "--record", "/work/my-enrollment/canonical.json", "--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/coordinator-public-key.hex", "--signing-key", "/keys/signing.hex", "--reviewed", "--reviewed-sha256", fmt.Sprintf("%x", sha256.Sum256(raw)), "--out", "/work/my-enrollment/enrollment.sig"}
		if err := p.open("decision-signer", "sign-enrollment", args); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	// Verify even when reopening an existing signature; existence is not success.
	if err := p.open("decision-signer", "verify-enrollment", []string{"mpc-ceremony", "inspect", "enrollment", "--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/coordinator-public-key.hex", "--enrollment", "/work/my-enrollment/canonical.json", "--enrollment-signature", "/work/my-enrollment/enrollment.sig"}); err != nil {
		return err
	}
	for _, pair := range [][2]string{{record, filepath.Join(p.d.Work, "enrollment.json")}, {sig, filepath.Join(p.d.Work, "enrollment.sig")}} {
		raw, err := readPreparationInput(pair[0])
		if err != nil {
			return err
		}
		if err := writePublicTextOnce(pair[1], string(raw)); err != nil {
			return err
		}
	}
	fmt.Fprintf(p.ui.output, "Enrollment verified. Send ONLY this public directory to the coordinator: %s\nRetain its disclosure subdirectory with the public evidence. Your private key stays in %s.\n", dir, p.d.Keys)
	return p.save()
}

func (p *rolePreparer) reviewEnrollmentDetails(raw []byte) error {
	fmt.Fprintln(p.ui.output, "Enrollment signing uses a network-disabled container. This does not disconnect or secure the host machine.")
	phrase := "REVIEWED"
	if p.d.Role == "release-signer" {
		fmt.Fprintln(p.ui.output, "The final-parameter signer's dedicated signing machine must be disconnected before continuing.")
		phrase = "OFFLINE AND REVIEWED"
	} else {
		fmt.Fprintln(p.ui.output, "Disconnecting the host is an additional precaution, not required for this enrollment. Follow any stricter agreed ceremony procedure. Your confirmation does not claim the host is offline.")
	}
	for {
		answer, err := p.ui.ask("Confirm this is YOUR accurate enrollment and disclosure; type "+phrase+", or DETAILS to inspect exact bytes", "")
		if err != nil {
			return err
		}
		if answer == "DETAILS" {
			fmt.Fprintf(p.ui.output, "Canonical public enrollment (control characters escaped):\n%q\n", raw)
			continue
		}
		if answer != phrase {
			return errors.New("cancelled; no signature approved")
		}
		return nil
	}
}

func (p *rolePreparer) reviewEnrollment() error {
	return p.reviewEnrollmentDetails(nil)
}

func writePublicTextOnce(path, text string) error {
	if raw, err := readPreparationInput(path); err == nil {
		if string(raw) == text {
			return nil
		}
		return errors.New("existing public file differs; preserve it and review before changing")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(text)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func (f *roleFlow) reviewOfflineRecord(command []string) (string, error) {
	path := commandValue(command, "record")
	if path == "" {
		return "", errors.New("offline operational signing requires an exact record")
	}
	local, err := f.publicHostPath(path)
	if err != nil {
		return "", err
	}
	raw, err := readPreparationInput(local)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(strings.TrimSpace(string(raw)), "{") {
		return "", errors.New("expected canonical public JSON")
	}
	fmt.Fprintf(f.ui.output, "Exact public record to sign:\n%s\n", raw)
	err = f.ui.confirm("Confirm that these are YOUR truthful observations. Disconnect the signing host; Docker network isolation alone is not host disconnection", "OFFLINE AND REVIEWED")
	return fmt.Sprintf("%x", sha256.Sum256(raw)), err
}
