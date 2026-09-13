package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Unsigned coordination instructions, not an enrollment or proof of issuance.
// The owner reviews them and signs the actual enrollment using proof-tool.
type observerSetup struct {
	Schema           string        `json:"schema"`
	CeremonyID       string        `json:"ceremony_id"`
	DefinitionSHA256 string        `json:"definition_sha256"`
	Role             string        `json:"role"`
	Index            int           `json:"role_index"`
	Identity         setupIdentity `json:"identity"`
}

func (s observerSetup) validate() error {
	if s.Schema != "relay-observer-setup-v1" || s.CeremonyID == "" || !sha256HexPattern.MatchString(s.DefinitionSHA256) || (s.Role != "witness" && s.Role != "mirror") || s.Index < 1 || s.Index > 65535 {
		return errors.New("invalid observer setup instructions")
	}
	return s.Identity.check()
}

func observerIdentityConflict(a, b setupIdentity) bool {
	return a.ID == b.ID || a.KeyID == b.KeyID || a.Fingerprint == b.Fingerprint || a.PublicKey == b.PublicKey
}

// The shared reservation-directory lock covers all profiles using this work
// folder. Reservations are permanent; issued-but-unused numbers are not recycled.
func reserveObserverSetup(root string, requested observerSetup, occupied []observerSetup) (string, error) {
	lock, err := acquireParticipantRunLock("", root)
	if err != nil {
		return "", err
	}
	defer lock.release()
	entries, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.Name() == ".relay-workspace.lock" {
			continue
		}
		if strings.HasPrefix(entry.Name(), ".public-import-") {
			return "", errors.New("interrupted observer reservation present; inspect retained files before issuing another")
		}
		var s observerSetup
		if err := setupReadJSON(filepath.Join(root, entry.Name()), &s); err != nil {
			return "", err
		}
		if err := s.validate(); err != nil {
			return "", err
		}
		occupied = append(occupied, s)
	}
	used := map[int]bool{}
	slots := map[string]observerSetup{}
	identities := map[string]observerSetup{}
	var same *observerSetup
	for _, s := range occupied {
		if err := s.validate(); err != nil {
			return "", err
		}
		slot := fmt.Sprintf("%s/%d", s.Role, s.Index)
		if old, ok := slots[slot]; ok && old != s {
			return "", errors.New("existing observer reservations conflict; review before issuing another")
		}
		slots[slot] = s
		for _, key := range []string{"id:" + s.Identity.ID, "key:" + s.Identity.KeyID, "pub:" + s.Identity.PublicKey} {
			if old, ok := identities[key]; ok && old != s {
				return "", errors.New("observer identity has conflicting existing reservations")
			}
			identities[key] = s
		}
		if s.CeremonyID != requested.CeremonyID || s.DefinitionSHA256 != requested.DefinitionSHA256 {
			return "", errors.New("observer reservation belongs to another definition; preserve it and investigate")
		}
		if observerIdentityConflict(s.Identity, requested.Identity) {
			if s.Identity != requested.Identity || s.Role != requested.Role || (same != nil && same.Index != s.Index) {
				return "", errors.New("observer identity already has a conflicting role, key or number")
			}
			copy := s
			same = &copy
		}
		if s.Role == requested.Role {
			used[s.Index] = true
		}
	}
	if same != nil {
		requested.Index = same.Index
	} else {
		requested.Index = 1
		for used[requested.Index] {
			requested.Index++
		}
	}
	if err := requested.validate(); err != nil {
		return "", err
	}
	for _, s := range occupied {
		if s.Role == requested.Role && s.Index == requested.Index && s.Identity != requested.Identity {
			return "", errors.New("observer number has conflicting recipients")
		}
	}
	path := filepath.Join(root, fmt.Sprintf("%s-%d.json", requested.Role, requested.Index))
	raw, err := json.Marshal(requested)
	if err != nil {
		return "", err
	}
	return path, publishPublicInput(path, raw)
}

func (f *roleFlow) prepareObserverSetup() error {
	d, err := f.authenticatedDefinition()
	if err != nil {
		return err
	}
	requirements, err := d.RequireJourney()
	if err != nil {
		return err
	}
	definitionPath := filepath.Join(f.state.Profile.Work, "ceremony/public/ceremony.json")
	hash, err := setupFileHash(definitionPath)
	if err != nil {
		return err
	}
	role, err := f.ui.choose("Prepare setup instructions for", "", []setupChoice{{"witness", "Witness"}, {"mirror", "Mirror"}})
	if err != nil {
		return err
	}
	source, err := f.ui.required("Absolute path to that observer's public identity.json", "")
	if err != nil {
		return err
	}
	var identity setupIdentity
	if err := setupReadJSON(source, &identity); err != nil {
		return err
	}
	if err := identity.check(); err != nil {
		return err
	}
	for _, e := range requirements.RequiredEnrollments {
		raw, _ := json.Marshal(e.Identity)
		var fixed setupIdentity
		if err := json.Unmarshal(raw, &fixed); err != nil {
			return err
		}
		if observerIdentityConflict(identity, fixed) {
			return errors.New("observer must use a distinct identity/key from the fixed ceremony roster")
		}
	}
	fmt.Fprintf(f.ui.output, "Recipient: %q (%s)\nPublic key fingerprint: %s\n", identity.DisplayName, identity.ID, identity.Fingerprint)
	if err := f.ui.confirm("Confirm this public identity with its owner through your independent channel. Create unsigned setup instructions only; this does not enroll or sign for them", "VERIFIED"); err != nil {
		return err
	}
	// Existing enrollments reserve their slots even when additional setup files
	// were never issued. Malformed/incomplete imports block allocation, not ignored.
	var occupied []observerSetup
	collection := filepath.Join(f.state.Profile.Work, "ceremony/public/collected-enrollments")
	dirs, err := os.ReadDir(collection)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, dir := range dirs {
		if !dir.IsDir() {
			return errors.New("unexpected enrollment collection entry; review before assigning numbers")
		}
		path := filepath.Join(collection, dir.Name())
		raw, err := readEnrollmentPublicFile(path, "canonical.json")
		if err != nil {
			return err
		}
		if _, err := readEnrollmentPublicFile(path, "enrollment.sig"); err != nil {
			return err
		}
		var e struct {
			CeremonyID string        `json:"ceremony_id"`
			Role       string        `json:"role"`
			Index      int           `json:"role_index"`
			Identity   setupIdentity `json:"identity"`
		}
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		if e.CeremonyID != d.CeremonyID || e.Index < 1 || e.Index > 65535 || e.Identity.check() != nil {
			return errors.New("incomplete imported enrollment; review before assigning numbers")
		}
		switch e.Role {
		case "public-witness":
			e.Role = "witness"
		case "mirror-operator":
			e.Role = "mirror"
		default:
			if observerIdentityConflict(e.Identity, identity) {
				return errors.New("identity already used by an imported enrollment")
			}
			continue
		}
		occupied = append(occupied, observerSetup{"relay-observer-setup-v1", d.CeremonyID, hash, e.Role, e.Index, e.Identity})
	}
	if after, err := setupFileHash(definitionPath); err != nil || after != hash {
		return errors.New("definition changed while preparing observer setup")
	}
	s := observerSetup{Schema: "relay-observer-setup-v1", CeremonyID: d.CeremonyID, DefinitionSHA256: hash, Role: role, Identity: identity}
	path, err := reserveObserverSetup(filepath.Join(f.state.Profile.Work, "ceremony/public/observer-setups"), s, occupied)
	if err != nil {
		return err
	}
	fmt.Fprintf(f.ui.output, "Send ONLY this public setup file to %q through your agreed channel:\n  %s\nThey import it with setup action 3, option 9. Relay then fills their enrollment number. Keep this reservation even if unused; it does not count as an enrollment.\n", identity.DisplayName, path)
	return nil
}

func (p *rolePreparer) importObserverSetup() error {
	source, err := p.ui.required("Path to the observer setup JSON supplied by your coordinator", "")
	if err != nil {
		return err
	}
	var s observerSetup
	if err := setupReadJSON(source, &s); err != nil {
		return err
	}
	if err := p.checkObserverSetup(s); err != nil {
		return err
	}
	fmt.Fprintf(p.ui.output, "Setup instruction: %s %d for %q. This file is unsigned; it is not an enrollment or proof of coordinator issuance.\n", s.Role, s.Index, s.Identity.DisplayName)
	if err := p.ui.confirm("Confirm these are the setup instructions you received from your coordinator through the agreed channel", "REVIEWED"); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return publishPublicInput(filepath.Join(p.d.Work, "observer-setup.json"), raw)
}

func (p *rolePreparer) checkObserverSetup(s observerSetup) error {
	if err := s.validate(); err != nil {
		return err
	}
	var identity setupIdentity
	if err := setupReadJSON(filepath.Join(p.d.Keys, "identity.json"), &identity); err != nil {
		return err
	}
	if s.Role != p.d.Role || s.Identity != identity {
		return errors.New("observer setup is for a different role or identity")
	}
	path := filepath.Join(p.d.Work, "ceremony/public/ceremony.json")
	before, err := setupFileHash(path)
	if err != nil {
		return err
	}
	d, err := p.authenticatedSetupDefinition()
	if err != nil {
		return err
	}
	after, err := setupFileHash(path)
	if err != nil || before != after || before != s.DefinitionSHA256 || d.CeremonyID != s.CeremonyID {
		return errors.New("observer setup does not match your authenticated ceremony definition")
	}
	if old := p.d.Values["enrollment-index"]; old != "" && old != strconv.Itoa(s.Index) {
		return errors.New("observer setup conflicts with your saved enrollment number")
	}
	return nil
}

func (p *rolePreparer) observerEnrollmentIndex() (string, error) {
	path := filepath.Join(p.d.Work, "observer-setup.json")
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		// Preserve pre-existing drafts; new observers obtain an assigned setup file.
		if old := p.d.Values["enrollment-index"]; old != "" {
			n, err := strconv.Atoi(old)
			if err != nil || n < 1 || n > 65535 {
				return "", errors.New("invalid saved observer number")
			}
			fmt.Fprintf(p.ui.output, "Using your previously saved %s number: %d\n", p.d.Role, n)
			return old, nil
		}
		fmt.Fprintln(p.ui.output, "Ask the coordinator to prepare your witness/mirror setup file from the enrollment collection menu. You do not need to choose a number yourself.")
		if err := p.importObserverSetup(); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	var s observerSetup
	if err := setupReadJSON(path, &s); err != nil {
		return "", err
	}
	if err := p.checkObserverSetup(s); err != nil {
		return "", err
	}
	fmt.Fprintf(p.ui.output, "Your %s number: %d (from your reviewed setup file)\n", s.Role, s.Index)
	return strconv.Itoa(s.Index), nil
}
