package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/zksecurity/relay/internal/access"
)

func (p *rolePreparer) transportRole() string {
	if p.d.Role == "upload-station" {
		return "release"
	}
	return p.d.Role
}

func (p *rolePreparer) phaseProfilePresent(phase string) bool {
	return regularPreparationFile(filepath.Join(p.d.Work, "ceremony/config", p.transportRole()+"-"+phase+".json"))
}

// Presence only controls navigation. Existing commands still authenticate inputs.
// Older prepared roles are not asked to recreate historical delivery reports.
func (p *rolePreparer) historicalOnboarding() bool {
	return p.phaseProfilePresent("phase1") || p.phaseProfilePresent("phase2")
}

func (p *rolePreparer) publicHandoffDigest(kind string) (string, string, error) {
	path := filepath.Join(p.d.Keys, "identity.json")
	if kind == "enrollment" {
		path = filepath.Join(p.d.Work, "my-enrollment")
		for _, name := range []string{"canonical.json", "enrollment.sig"} {
			if _, err := readPreparationInput(filepath.Join(path, name)); err != nil {
				return path, "", err
			}
		}
		digest, err := flowTreeHash(path)
		return path, digest, err
	}
	if kind != "identity" {
		return "", "", errors.New("unknown public handoff")
	}
	if _, err := readPreparationInput(path); err != nil {
		return path, "", err
	}
	digest, err := setupFileHash(path)
	return path, digest, err
}

func (p *rolePreparer) publicHandoffReported(kind string) bool {
	_, digest, err := p.publicHandoffDigest(kind)
	return err == nil && digest != "" && p.d.Values["handoff/"+kind] == digest
}

func (p *rolePreparer) reportPublicHandoff(kind string) error {
	path, digest, err := p.publicHandoffDigest(kind)
	if err != nil {
		return fmt.Errorf("prepare your public %s first: %w", kind, err)
	}
	fmt.Fprintf(p.ui.output, "Send ONLY this public %s to your coordinator:\n  %s\n", kind, path)
	if kind == "identity" {
		fmt.Fprintln(p.ui.output, "If joining through Tessera, upload identity.json on your invitation page. Otherwise use your agreed coordination channel. Ask the coordinator for ceremony.json, ceremony.sig and the independently authenticated coordinator public key next.")
	} else {
		fmt.Fprintln(p.ui.output, "Send the complete my-enrollment public folder, including canonical.json, enrollment.sig and its disclosure subdirectory. The coordinator must verify it; sending is not acceptance.")
	}
	fmt.Fprintln(p.ui.output, "Never send signing.hex, the keys folder, credentials or private grants.")
	choice, err := p.ui.choose("Public handoff", "", []setupChoice{{"sent", "I sent these exact public files"}, {"waiting", "Not yet — return and keep this step waiting"}})
	if err != nil || choice == "waiting" {
		return err
	}
	_, after, err := p.publicHandoffDigest(kind)
	if err != nil || after != digest {
		return errors.New("public files changed during review; review and send the exact files again")
	}
	p.d.Values["handoff/"+kind] = digest
	fmt.Fprintln(p.ui.output, "Sending reported by you. Recipient receipt, review and acceptance are not verified.")
	return p.save()
}

func (p *rolePreparer) requirePublicStorage() error {
	path := filepath.Join(p.d.Work, "ceremony/config/relay-storage.json")
	var storage access.StorageConfig
	if _, err := readPreparationInput(path); err == nil {
		if err := setupReadJSON(path, &storage); err == nil {
			if err := storage.Validate(); err == nil {
				return nil
			}
		}
	}
	return fmt.Errorf("ask your coordinator for the PUBLIC relay-storage.json, then choose 3) Import a received public file -> 4) Public storage configuration. Expected local file: %s. This is not a private upload grant or credentials. The coordinator creates it with 10) Configure storage in coordinator preparation", path)
}
