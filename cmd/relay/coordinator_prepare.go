package main

// This authors unsigned initialization inputs. proof-tool remains responsible
// for protocol validation, canonical input acceptance and all signature checks.
import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zksecurity/relay/contracts/setupv2"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	releaseassets "github.com/zksecurity/relay/release"
)

type setupIdentity struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"ed25519_public_key_hex"`
	Fingerprint string `json:"public_key_fingerprint"`
}
type setupParticipant struct {
	Identity setupIdentity `json:"identity"`
}
type setupRoster struct {
	Coordinator   setupIdentity      `json:"coordinator"`
	ReleaseSigner setupIdentity      `json:"release_signer"`
	Auditors      []setupIdentity    `json:"auditors"`
	Roster        []setupParticipant `json:"roster"`
}
type setupPhase struct {
	Participants []string `json:"participants"`
	Minimum      int      `json:"minimum"`
}
type setupBeacon struct {
	Provider   string `json:"provider"`
	Network    string `json:"network"`
	ChainHash  string `json:"chain_hash_hex"`
	PublicKey  string `json:"public_key_hex"`
	Scheme     string `json:"scheme"`
	Genesis    int64  `json:"genesis_time_unix"`
	Period     uint32 `json:"period_seconds"`
	Extraction string `json:"extraction"`
	Challenge  uint16 `json:"minimum_challenge_bytes"`
	Lead       uint32 `json:"minimum_witness_lead_seconds"`
	Future     bool   `json:"future_round_required"`
}
type setupPolicy struct {
	Phase1 setupPhase  `json:"phase1_policy"`
	Phase2 setupPhase  `json:"phase2_policy"`
	Beacon setupBeacon `json:"beacon_policy"`
}
type setupBinary struct{ Path, SHA256 string }
type coordinatorDraft struct {
	TesseraSetup                             *setupv2.Setup  `json:"tessera_setup,omitempty"`
	Tessera                                  *tesseraContext `json:"tessera_context,omitempty"`
	ArchitecturePolicy                       string          `json:"architecture_policy,omitempty"`
	Schema, Name, Release, Work, Trust, Keys string
	Mode, Circuit, Status, CreatedAt         string
	Identities                               setupRoster
	Policy                                   setupPolicy
	Binaries                                 []setupBinary
	Storage                                  map[string]string
	Credentials                              string
	PolicyTemplate                           string
	R2Parent                                 string `json:"r2_parent_credential,omitempty"`
	R2Control                                string `json:"r2_control_credential,omitempty"`
	OfflinePreparation                       bool   `json:"offline_preparation,omitempty"`
	SessionCredentials                       bool   `json:"session_credentials,omitempty"`
}

func setupReadJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("input must be a regular JSON file smaller than 1 MiB")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	// Requiring the compact fixed-field encoding also rejects duplicate fields.
	canonical, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return err
	}
	if !bytes.Equal(canonical, compact.Bytes()) {
		return errors.New("use the original public JSON with canonical field order; duplicate or reordered fields are not accepted")
	}
	return nil
}

func (i setupIdentity) check() error {
	pub, err := hex.DecodeString(i.PublicKey)
	if err != nil || len(pub) != 32 || i.ID == "" || i.KeyID == "" || i.DisplayName == "" {
		return errors.New("invalid public identity; use identity.json from proof-tool identity generate")
	}
	sum := sha256.Sum256(pub)
	if i.Fingerprint != fmt.Sprintf("sha256:%x", sum) {
		return errors.New("public identity fingerprint does not match its key")
	}
	return nil
}

func (d coordinatorDraft) validate() error {
	if d.Schema != "relay-coordinator-draft-v1" || !guidedName.MatchString(d.Name) || (!launcherReleaseTag.MatchString(d.Release) && d.Release != "LOCAL-REHEARSAL") {
		return errors.New("invalid draft identity or release")
	}
	if d.Release == "LOCAL-REHEARSAL" && (d.Mode != "rehearsal" || d.Circuit != "rehearsal-tiny-v1") {
		return errors.New("local testing permits only the tiny rehearsal circuit")
	}
	if d.Mode != "rehearsal" && d.Mode != "production" {
		return errors.New("choose rehearsal or production explicitly")
	}
	if d.Circuit != "ownership-destination-v2" && !(d.Mode == "rehearsal" && d.Circuit == "rehearsal-tiny-v1") {
		return errors.New("choose the supported production circuit, or the tiny circuit in rehearsal mode only")
	}
	seenID, seenKey, seenPub := map[string]bool{}, map[string]bool{}, map[string]bool{}
	identities := []setupIdentity{d.Identities.Coordinator, d.Identities.ReleaseSigner}
	identities = append(identities, d.Identities.Auditors...)
	for _, p := range d.Identities.Roster {
		identities = append(identities, p.Identity)
	}
	for _, i := range identities {
		if err := i.check(); err != nil {
			return err
		}
		if seenID[i.ID] || seenKey[i.KeyID] || seenPub[i.Fingerprint] {
			return errors.New("assigned roles need distinct identity IDs, key IDs and public keys; this does not check independent people")
		}
		seenID[i.ID], seenKey[i.KeyID], seenPub[i.Fingerprint] = true, true, true
	}
	if d.ArchitecturePolicy != "" && d.ArchitecturePolicy != "both" && d.ArchitecturePolicy != "single" && d.ArchitecturePolicy != "custom" {
		return errors.New("invalid architecture policy")
	}
	if len(d.Identities.Auditors) < 2 || len(d.Identities.Roster) == 0 {
		return errors.New("assign at least two auditors, a final-parameter signer and one participant")
	}
	roster := map[string]bool{}
	for _, p := range d.Identities.Roster {
		roster[p.Identity.ID] = true
	}
	for _, phase := range []setupPhase{d.Policy.Phase1, d.Policy.Phase2} {
		if phase.Minimum < 1 || phase.Minimum > len(phase.Participants) || phase.Minimum > 255 {
			return errors.New("phase minimum must be between 1 and its scheduled participant count (at most 255)")
		}
		seen := map[string]bool{}
		for _, id := range phase.Participants {
			if !roster[id] || seen[id] {
				return errors.New("phase orders must contain distinct assigned participant IDs")
			}
			seen[id] = true
		}
	}
	if d.Policy.Beacon.Provider == "" || !d.Policy.Beacon.Future || d.Policy.Beacon.Lead == 0 {
		return errors.New("import a reviewed beacon policy requiring a future round and witness lead time")
	}
	return nil
}

// Draft updates are atomic and performed only while the per-work-directory
// lock is held. Initialization attempts freeze the draft before child execution.
func saveCoordinatorDraft(path string, d coordinatorDraft) error {
	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if st, err := os.Lstat(path); err == nil && (!st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0) {
		return errors.New("draft is not a private regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".draft-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func setupWriteNew(path string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

type coordinatorWizard struct {
	d                     coordinatorDraft
	input                 *bufio.Reader
	output                io.Writer
	draftPath             string
	run                   func([]string) error
	localAction           func(string, string, []string, bool) error
	continueFlow          func() error
	prepareBinaries       func() error
	readSecret            func(string) (string, error)
	credentialRoot        string
	sessionCredentialDirs []string
	interrupted           <-chan struct{}
}

func (w *coordinatorWizard) ask(label, current string) (string, error) {
	if w.interrupted != nil {
		select {
		case <-w.interrupted:
			return "", errSecretPromptInterrupted
		default:
		}
	}
	if current == "" {
		fmt.Fprintf(w.output, "%s: ", label)
	} else {
		fmt.Fprintf(w.output, "%s [%s]: ", label, current)
	}
	var value string
	var err error
	if w.interrupted == nil {
		value, err = w.input.ReadString('\n')
	} else {
		type result struct {
			value string
			err   error
		}
		done := make(chan result, 1)
		go func() { v, e := w.input.ReadString('\n'); done <- result{v, e} }()
		select {
		case <-w.interrupted:
			return "", errSecretPromptInterrupted
		case r := <-done:
			value, err = r.value, r.err
		}
	}
	if err != nil {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return current, nil
	}
	return value, nil
}
func (w *coordinatorWizard) required(label, current string) (string, error) {
	for {
		value, err := w.ask(label, current)
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(value) != "" {
			return value, nil
		}
		fmt.Fprintln(w.output, "This value is required. Please enter it, or press Ctrl-C to stop.")
	}
}

type setupChoice struct{ value, label string }

func (w *coordinatorWizard) choose(label, current string, choices []setupChoice) (string, error) {
	if len(choices) == 0 {
		return "", errors.New("no choices available yet")
	}
	fmt.Fprintln(w.output, label)
	defaultNumber := ""
	byNumber := map[int]string{}
	nextNumber := 1
	for _, c := range choices {
		number := nextNumber
		if c.value == "cancel" {
			number = 0
		} else {
			nextNumber++
		}
		byNumber[number] = c.value
		fmt.Fprintf(w.output, "%d) %s\n", number, c.label)
		if c.value == current {
			defaultNumber = strconv.Itoa(number)
		}
	}
	for {
		answer, err := w.required("Choose a number", defaultNumber)
		if err != nil {
			return "", err
		}
		n, err := strconv.Atoi(answer)
		if value, ok := byNumber[n]; err == nil && ok {
			return value, nil
		}
		fmt.Fprintln(w.output, "Enter one of the displayed numbers.")
	}
}

func (w *coordinatorWizard) participantOrder(label string, current []string) ([]string, error) {
	if len(w.d.Identities.Roster) == 0 {
		return nil, errors.New("import participants before choosing their order")
	}
	fmt.Fprintln(w.output, label)
	positions := map[string]string{}
	for n, p := range w.d.Identities.Roster {
		fmt.Fprintf(w.output, "%d) %s (%s)\n", n+1, p.Identity.DisplayName, p.Identity.ID)
		positions[p.Identity.ID] = strconv.Itoa(n + 1)
	}
	defaults := []string{}
	for _, id := range current {
		if positions[id] == "" {
			defaults = nil
			break
		}
		defaults = append(defaults, positions[id])
	}
	for {
		answer, err := w.required("Participant numbers in order, separated by commas (for example 2,1)", strings.Join(defaults, ","))
		if err != nil {
			return nil, err
		}
		ids := []string{}
		seen := map[int]bool{}
		valid := true
		for _, part := range strings.Split(answer, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil || n < 1 || n > len(w.d.Identities.Roster) || seen[n] {
				valid = false
				break
			}
			seen[n] = true
			ids = append(ids, w.d.Identities.Roster[n-1].Identity.ID)
		}
		if valid {
			return ids, nil
		}
		fmt.Fprintln(w.output, "Use each listed number at most once; empty or unknown entries are not allowed.")
	}
}
func (w *coordinatorWizard) confirm(label, exact string) error {
	value, err := w.ask(label+"; type "+exact, "")
	if err != nil {
		return err
	}
	if value != exact {
		return errors.New("cancelled; no action approved")
	}
	return nil
}
func (w *coordinatorWizard) save() error { return saveCoordinatorDraft(w.draftPath, w.d) }
func (w *coordinatorWizard) summary() {
	fmt.Fprintf(w.output, "\nStatus: %s\nCeremony: %s\nMode: %s\nCircuit: %s\nRelease: %s\n", w.d.Status, w.d.Name, w.d.Mode, w.d.Circuit, w.d.Release)
	show := func(role string, i setupIdentity) {
		fmt.Fprintf(w.output, "%s: %q (%q), key %s\n", role, i.DisplayName, i.ID, i.Fingerprint)
	}
	show("Coordinator", w.d.Identities.Coordinator)
	show("Final-parameter signer", w.d.Identities.ReleaseSigner)
	for _, i := range w.d.Identities.Auditors {
		show("Auditor", i)
	}
	for _, p := range w.d.Identities.Roster {
		show("Participant", p.Identity)
	}
	fmt.Fprintln(w.output, "Different keys do not prove these are different people or organizations.")
	for n, p := range []setupPhase{w.d.Policy.Phase1, w.d.Policy.Phase2} {
		fmt.Fprintf(w.output, "Phase %d order: %s; at least %d contributions required.\n", n+1, strings.Join(p.Participants, " -> "), p.Minimum)
	}
	b := w.d.Policy.Beacon
	fmt.Fprintf(w.output, "Beacon: %s / %s; witnesses get at least %d seconds of lead time; future round required: %t.\nBeacon chain hash: %s\n", b.Provider, b.Network, b.Lead, b.Future, b.ChainHash)
	fmt.Fprintln(w.output, "The beacon supplies public randomness after contributions close. The full policy is saved in draft.json; proof-tool validates it before signing.")
	for _, b := range w.d.Binaries {
		fmt.Fprintf(w.output, "Additional allowed proof-tool binary: %s SHA-256 %s\n", b.Path, b.SHA256)
	}
	if w.d.ArchitecturePolicy == "both" || (w.d.ArchitecturePolicy == "" && len(w.d.Binaries) == 0 && w.localAction == nil) {
		fmt.Fprintln(w.output, "Supported computers: Intel/AMD and ARM64, including Apple silicon through Docker. Exact release builds are authenticated before initialization.")
	} else if len(w.d.Binaries) == 0 {
		fmt.Fprintln(w.output, "Supported computers: this machine's Linux architecture only.")
	}
	fmt.Fprintln(w.output, "Witness/mirror enrollments happen AFTER initialization. Identity distribution is manual. Storage setup does not create buckets or grant cloud permissions.")
}

func (w *coordinatorWizard) basics() error {
	mode, err := w.choose("Ceremony mode", w.d.Mode, []setupChoice{{"rehearsal", "Rehearsal — test only"}, {"production", "Production — real ceremony"}})
	if err != nil {
		return err
	}
	circuit, err := w.choose("Circuit", w.d.Circuit, []setupChoice{{"ownership-destination-v2", "Ownership destination v2 — production circuit"}, {"rehearsal-tiny-v1", "Tiny test circuit — rehearsal only"}})
	if err != nil {
		return err
	}
	if mode != "rehearsal" && mode != "production" {
		return errors.New("invalid mode")
	}
	if circuit != "ownership-destination-v2" && !(mode == "rehearsal" && circuit == "rehearsal-tiny-v1") {
		return errors.New("tiny circuit is rehearsal-only")
	}
	if w.localAction != nil && (mode != "rehearsal" || circuit != "rehearsal-tiny-v1") {
		return errors.New("this local test build only permits rehearsal / rehearsal-tiny-v1")
	}
	w.d.Mode, w.d.Circuit = mode, circuit
	return w.save()
}
func (w *coordinatorWizard) identity() error {
	role, err := w.choose("Import role", "", []setupChoice{{"coordinator", "Coordinator"}, {"release-signer", "Final-parameter signer"}, {"auditor", "Auditor"}, {"participant", "Participant"}})
	if err != nil {
		return err
	}
	path, err := w.required("Absolute path to that role's public identity.json (never a private key)", "")
	if err != nil {
		return err
	}
	var i setupIdentity
	if err := setupReadJSON(path, &i); err != nil {
		return err
	}
	if err := i.check(); err != nil {
		return err
	}
	fmt.Fprintf(w.output, "Identity %q (%q), fingerprint %s\n", i.ID, i.DisplayName, i.Fingerprint)
	if err := w.confirm("Compare the full fingerprint above with the owner's copy through your agreed independent channel. Confirm only if they match", "VERIFIED"); err != nil {
		return err
	}
	switch role {
	case "coordinator":
		w.d.Identities.Coordinator = i
	case "release-signer":
		w.d.Identities.ReleaseSigner = i
	case "auditor":
		for n, old := range w.d.Identities.Auditors {
			if old.ID == i.ID {
				w.d.Identities.Auditors[n] = i
				return w.save()
			}
		}
		w.d.Identities.Auditors = append(w.d.Identities.Auditors, i)
	case "participant":
		for n, old := range w.d.Identities.Roster {
			if old.Identity.ID == i.ID {
				w.d.Identities.Roster[n] = setupParticipant{i}
				return w.save()
			}
		}
		w.d.Identities.Roster = append(w.d.Identities.Roster, setupParticipant{i})
	default:
		return errors.New("unknown role; witnesses and mirrors enroll after initialization")
	}
	return w.save()
}
func (w *coordinatorWizard) policy() error {
	choices := []setupChoice{{"standard", "Use the standard beacon settings included with this Relay release"}, {"custom", "Advanced: load a custom policy file"}}
	defaultChoice := "standard"
	if w.d.Policy.Beacon.Provider != "" {
		choices = append([]setupChoice{{"current", "Keep the saved beacon settings"}}, choices...)
		defaultChoice = "current"
	}
	selection, err := w.choose("Beacon settings", defaultChoice, choices)
	if err != nil {
		return err
	}
	var policy setupPolicy
	path := ""
	switch selection {
	case "current":
		policy, path = w.d.Policy, w.d.PolicyTemplate
	case "standard":
		if err := json.Unmarshal(releaseassets.CeremonyPolicy(), &policy); err != nil {
			return fmt.Errorf("invalid built-in policy: %w", err)
		}
	case "custom":
		path, err = w.required("Path to your reviewed custom policy JSON", w.d.PolicyTemplate)
		if err != nil {
			return err
		}
		if err := setupReadJSON(path, &policy); err != nil {
			return err
		}
	}
	suggested := []string{}
	for _, p := range w.d.Identities.Roster {
		suggested = append(suggested, p.Identity.ID)
	}
	for n, p := range []*setupPhase{&policy.Phase1, &policy.Phase2} {
		previous := []setupPhase{w.d.Policy.Phase1, w.d.Policy.Phase2}[n]
		defaultOrder := suggested
		if len(previous.Participants) > 0 {
			defaultOrder = previous.Participants
		}
		order, err := w.participantOrder(fmt.Sprintf("Phase %d contribution order", n+1), defaultOrder)
		if err != nil {
			return err
		}
		p.Participants = order
		defaultMinimum := len(p.Participants)
		if previous.Minimum > 0 {
			defaultMinimum = previous.Minimum
		}
		if defaultMinimum > len(order) {
			defaultMinimum = len(order)
		}
		for {
			minimum, err := w.required(fmt.Sprintf("Phase %d minimum contributions required before closure", n+1), strconv.Itoa(defaultMinimum))
			if err != nil {
				return err
			}
			p.Minimum, err = strconv.Atoi(minimum)
			if err == nil && p.Minimum >= 1 && p.Minimum <= len(order) {
				break
			}
			fmt.Fprintf(w.output, "Enter a number from 1 to %d.\n", len(order))
		}
	}
	b := policy.Beacon
	fmt.Fprintf(w.output, "Beacon: %s / %s. Witnesses must observe at least %d seconds before the beacon round. Future round required: %t.\nThe beacon provides public randomness after contributions close; Relay does not substitute another round.\nChain hash: %s\nPublic key: %s\n", b.Provider, b.Network, b.Lead, b.Future, b.ChainHash, b.PublicKey)
	if err := w.confirm("Review these beacon settings and the participant orders/minimums you selected; proof-tool still validates the complete policy before signing", "REVIEWED"); err != nil {
		return err
	}
	w.d.Policy = policy
	w.d.PolicyTemplate = path
	return w.save()
}
func setupFileHash(path string) (string, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", errors.New("expected a regular file, not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (w *coordinatorWizard) binary() error {
	current := w.d.ArchitecturePolicy
	if current == "" {
		current = "both"
		if len(w.d.Binaries) > 0 {
			current = "custom"
		}
	}
	choice, err := w.choose("Supported computers", current, []setupChoice{{"both", "Intel/AMD and ARM64 — verified builds from this release"}, {"single", "Advanced: this machine's architecture only"}, {"custom", "Advanced: add another reviewed binary file"}})
	if err != nil {
		return err
	}
	if choice != "custom" {
		if w.localAction != nil && choice == "both" {
			return errors.New("this legacy local harness only supports its current architecture")
		}
		w.d.ArchitecturePolicy = choice
		w.d.Binaries = nil
		return w.save()
	}
	path, err := w.required("Additional approved Linux proof-tool binary, absolute path", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		return errors.New("absolute path required")
	}
	digest, err := setupFileHash(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(w.output, "Binary SHA-256: %s\n", digest)
	if err := w.confirm("Compare the full SHA-256 above with the approved proof-tool release through your agreed channel", "VERIFIED"); err != nil {
		return err
	}
	w.d.Binaries = append(w.d.Binaries, setupBinary{path, digest})
	w.d.ArchitecturePolicy = "custom"
	return w.save()
}

func (w *coordinatorWizard) action(name, role string, command []string, credentials bool) error {
	if w.localAction != nil {
		return w.localAction(name, role, command, credentials)
	}
	// Each action gets a content-derived alias; existing launcher activity records
	// remain authoritative for replay/uncertain-attempt handling.
	raw, _ := json.Marshal(struct {
		Draft   coordinatorDraft
		Command []string
	}{w.d, command})
	sum := sha256.Sum256(raw)
	alias := fmt.Sprintf("prep-%s-%x", name, sum[:8])
	args := []string{"ceremony", "setup", alias, "--role", role, "--release", w.d.Release, "--work", w.d.Work, "--trust", w.d.Trust, "--keys", w.d.Keys}
	if role == "keygen" {
		args = []string{"ceremony", "setup", alias, "--role", role, "--release", w.d.Release, "--work", w.d.Keys}
	}
	if credentials {
		args = append(args, "--aws-credentials", w.d.Credentials)
		for _, pair := range [][2]string{{"--r2-parent-credential", w.d.R2Parent}, {"--r2-control-credential", w.d.R2Control}} {
			if pair[1] != "" {
				args = append(args, pair[0], pair[1])
			}
		}
	}
	args = append(args, "--")
	args = append(args, command...)
	openArgs := []string{"ceremony", "open", alias, "--role", role}
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	dir, err := guidedDirectory(root, alias, role)
	if err != nil {
		return err
	}
	profilePath := filepath.Join(dir, "profile.json")
	if _, err := os.Lstat(profilePath); err == nil {
		p, err := readGuidedProfile(profilePath, alias, role)
		if err != nil {
			return err
		}
		expectedWork, expectedTrust, expectedKeys := w.d.Work, w.d.Trust, w.d.Keys
		if role == "keygen" {
			expectedWork, expectedTrust, expectedKeys = w.d.Keys, "", ""
		}
		expectedCredentials := ""
		if credentials {
			expectedCredentials = w.d.Credentials
		}
		// Keygen automatically allocates an unused trust directory.
		if p.ReleaseCommit != strings.TrimPrefix(w.d.Release, "role-images-") || p.Work != expectedWork || p.Keys != expectedKeys || p.Credentials != expectedCredentials || !slices.Equal(p.Command, command) || (role != "keygen" && p.Trust != expectedTrust) {
			return errors.New("existing saved action differs from reviewed draft")
		}
		if credentials && (p.R2Parent != w.d.R2Parent || p.R2Control != w.d.R2Control) {
			return errors.New("existing saved action has different R2 credential file references")
		}
		if err := checkGuidedAttempts(filepath.Join(dir, "activity")); err != nil && !errors.Is(err, os.ErrNotExist) {
			if err := w.confirm("Earlier action failed or was interrupted. Review its output and container state first; this does not authorize overwriting files", "REVIEWED RETRY"); err != nil {
				return err
			}
			openArgs = append(openArgs, "--reviewed-retry")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := w.run(args); err != nil {
		fmt.Fprintf(w.output, "Saved-action alias: %s (%s). If this action was already prepared, review its activity and use ceremony open %s --role %s --reviewed-retry only when appropriate.\n", alias, role, alias, role)
		return err
	}
	fmt.Fprintf(w.output, "Saved-action alias: %s (%s). Keep this name for recovery.\n", alias, role)
	return w.run(openArgs)
}

func (w *coordinatorWizard) removeIdentity() error {
	choices := []setupChoice{}
	add := func(role string, i setupIdentity) {
		if i.ID != "" {
			choices = append(choices, setupChoice{i.ID, fmt.Sprintf("%s: %s (%s)", role, i.DisplayName, i.ID)})
		}
	}
	add("Coordinator", w.d.Identities.Coordinator)
	add("Final-parameter signer", w.d.Identities.ReleaseSigner)
	for _, i := range w.d.Identities.Auditors {
		add("Auditor", i)
	}
	for _, p := range w.d.Identities.Roster {
		add("Participant", p.Identity)
	}
	id, err := w.choose("Assignment to remove from the unsigned draft", "", choices)
	if err != nil {
		return err
	}
	if err := w.confirm("Remove the assignment only (no files or keys are deleted)", "REMOVE"); err != nil {
		return err
	}
	if w.d.Identities.Coordinator.ID == id {
		w.d.Identities.Coordinator = setupIdentity{}
	}
	if w.d.Identities.ReleaseSigner.ID == id {
		w.d.Identities.ReleaseSigner = setupIdentity{}
	}
	auditors := []setupIdentity{}
	for _, i := range w.d.Identities.Auditors {
		if i.ID != id {
			auditors = append(auditors, i)
		}
	}
	participants := []setupParticipant{}
	for _, p := range w.d.Identities.Roster {
		if p.Identity.ID != id {
			participants = append(participants, p)
		}
	}
	w.d.Identities.Auditors, w.d.Identities.Roster = auditors, participants
	fmt.Fprintln(w.output, "Review phase orders next: removed IDs are not silently removed from the policy.")
	return w.save()
}
func (w *coordinatorWizard) generateIdentity() error {
	for _, name := range []string{"signing.hex", "identity.json"} {
		if _, err := os.Lstat(filepath.Join(w.d.Keys, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("identity files already exist or cannot be checked; import your existing public identity instead")
		}
	}
	suffix, err := randomID()
	if err != nil {
		return err
	}
	id := "coordinator-" + suffix
	fmt.Fprintf(w.output, "Your coordinator identity ID (automatically assigned): %s\n", id)
	display, err := w.required("Your public display name", "")
	if err != nil {
		return err
	}
	if err := w.confirm("Generate only YOUR coordinator keypair in the protected keys folder", "GENERATE"); err != nil {
		return err
	}
	if err := w.action("identity", "keygen", []string{"mpc-ceremony", "identity", "generate", "--identity-id", id, "--display-name", display, "--private-key-out", "/work/signing.hex", "--public-identity-out", "/work/identity.json"}, false); err != nil {
		return err
	}
	publicPath := filepath.Join(w.d.Keys, "identity.json")
	fmt.Fprintf(w.output, "Send ONLY %s to the ceremony roles through your agreed channel. Keep signing.hex private.\n", publicPath)
	var generated setupIdentity
	if err := setupReadJSON(publicPath, &generated); err != nil {
		return err
	}
	if err := generated.check(); err != nil {
		return err
	}
	if generated.ID != id || generated.DisplayName != display {
		return errors.New("generated identity differs from the requested identity")
	}
	choice, err := w.choose("Assign this new identity to your coordinator role?", "assign", []setupChoice{{"assign", "Yes — use my new coordinator identity"}, {"later", "Not yet — keep the files without assigning"}})
	if err != nil {
		return err
	}
	if choice == "assign" {
		w.d.Identities.Coordinator = generated
		return w.save()
	}
	return nil
}

func (w *coordinatorWizard) initialize() error {
	if w.d.Tessera != nil || w.d.TesseraSetup != nil {
		if err := checkTesseraDraft(w.d); err != nil {
			return err
		}
	}
	if w.localAction != nil && (w.d.Mode != "rehearsal" || w.d.Circuit != "rehearsal-tiny-v1" || len(w.d.Binaries) != 0) {
		return errors.New("local tests require the tiny rehearsal circuit and the supplied local images only")
	}
	if w.d.Status != "draft" {
		return errors.New("initialization already attempted; edits and automatic retry are blocked")
	}
	if err := w.d.validate(); err != nil {
		return err
	}
	root := filepath.Join(w.d.Work, "ceremony")
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		return errors.New("ceremony output already exists or cannot be checked; preserve it and investigate")
	}
	if st, err := os.Lstat(filepath.Join(w.d.Keys, "signing.hex")); err != nil || !st.Mode().IsRegular() {
		return errors.New("coordinator signing.hex is missing or unsafe")
	}
	if w.prepareBinaries != nil {
		if err := w.prepareBinaries(); err != nil {
			return err
		}
	}
	w.summary()
	fmt.Fprintln(w.output, "This signs the definition and computes Phase 1 genesis. Production can require substantial RAM, disk and time. It does NOT publish or start participant turns.")
	if err := w.confirm("Approve exactly this draft", "INITIALIZE "+strings.ToUpper(w.d.Mode)); err != nil {
		return err
	}
	w.d.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	w.d.Status = "initialization-attempted"
	if err := w.save(); err != nil {
		return err
	}
	snapshot := filepath.Join(filepath.Dir(w.draftPath), "frozen")
	if err := os.Mkdir(snapshot, 0700); err != nil {
		return err
	}
	if err := setupWriteNew(filepath.Join(snapshot, "participants.json"), w.d.Identities); err != nil {
		return err
	}
	if err := setupWriteNew(filepath.Join(snapshot, "policy.json"), w.d.Policy); err != nil {
		return err
	}
	if err := setupWriteNew(filepath.Join(snapshot, "draft.json"), w.d); err != nil {
		return err
	}
	// The external trust anchor comes from the operator-confirmed identity, not
	// from a public-key file embedded in the generated transcript.
	trust := filepath.Join(w.d.Trust, "setup-coordinator.hex")
	f, err := os.OpenFile(trust, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(w.d.Identities.Coordinator.PublicKey)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Mkdir(root, 0700); err != nil {
		return err
	}
	command := []string{"mpc-ceremony", "init", "--mode", w.d.Mode, "--key-version", w.d.Circuit, "--created-at", w.d.CreatedAt, "--participants", "/work/coordinator-setup/frozen/participants.json", "--policy", "/work/coordinator-setup/frozen/policy.json", "--coordinator-key-id", w.d.Identities.Coordinator.KeyID, "--coordinator-signing-key", "/keys/signing.hex", "--out-dir", "/work/ceremony/public"}
	for n, b := range w.d.Binaries {
		// Copy first, then hash the copy. Never execute a host-provided binary.
		target := filepath.Join(snapshot, fmt.Sprintf("allowed-%d", n))
		src, err := os.Open(b.Path)
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, src)
		src.Close()
		closeErr := dst.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		digest, err := setupFileHash(target)
		if err != nil {
			return err
		}
		if digest != b.SHA256 {
			return errors.New("additional binary changed since review")
		}
		command = append(command, "--allowed-binary", fmt.Sprintf("/work/coordinator-setup/frozen/allowed-%d", n))
	}
	if err := w.action("initialize", "coordinator", command, false); err != nil {
		return err
	}
	return w.verify()
}
func (w *coordinatorWizard) verify() error {
	if w.d.Status == "draft" {
		return errors.New("nothing initialized yet")
	}
	// Do not retain a success label if a subsequent verification fails.
	w.d.Status = "initialization-attempted"
	if err := w.save(); err != nil {
		return err
	}
	if err := w.action("verify", "coordinator", []string{"mpc-ceremony", "inspect", "definition", "--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", "/trust/setup-coordinator.hex"}, false); err != nil {
		return err
	}
	w.d.Status = "definition-verified"
	if err := w.save(); err != nil {
		return err
	}
	fmt.Fprintln(w.output, "Signed definition verified by proof-tool. This does not verify all initialization artifacts or publish anything. Distribute the signed public definition for assignment review; collect witness/mirror enrollments next.")
	return nil
}

func (w *coordinatorWizard) storage() error {
	if err := w.requirePreviousSessionClosed(); err != nil {
		return err
	}
	choice, err := w.choose("Storage settings", "", []setupChoice{{"r2", "Set up Cloudflare R2 and credentials"}, {"import", "Import the administrator's settings file"}, {"advanced", "Advanced settings: enter infrastructure fields individually"}})
	if err != nil {
		return err
	}
	if choice == "import" {
		return w.importStorageSettings()
	}
	if choice == "r2" {
		return w.setupR2()
	}
	provider, err := w.choose("Storage provider", w.d.Storage["provider"], []setupChoice{{"aws", "Amazon S3 (AWS)"}, {"r2", "Cloudflare R2"}})
	if err != nil {
		return err
	}
	if provider != "aws" && provider != "r2" {
		return errors.New("choose aws or r2")
	}
	fields := storageSettingFields(provider)
	values := map[string]string{"provider": provider}
	fmt.Fprintln(w.output, "Use the administrator's provisioned resource details. Never paste secret keys or tokens here.")
	for _, field := range fields {
		value, err := w.required(field, w.d.Storage[field])
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("%s is required", field)
		}
		values[field] = value
	}
	credential, err := w.required("Absolute path to local AWS-format credentials FILE, not its contents", w.d.Credentials)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(credential) {
		return errors.New("absolute credential-file path required")
	}
	w.d.Storage, w.d.Credentials = values, credential
	w.d.R2Parent, w.d.R2Control, w.d.SessionCredentials = "", "", false
	return w.save()
}
func (w *coordinatorWizard) configureStorage() error {
	if w.localAction != nil {
		return errors.New("cloud storage operations are disabled in the local test harness")
	}
	if w.d.Status != "definition-verified" {
		return errors.New("verify the initialized definition before configuring storage")
	}
	if w.d.Storage["provider"] == "" {
		return errors.New("enter administrator-supplied storage settings first")
	}
	raw, _ := json.MarshalIndent(w.d.Storage, "", "  ")
	fmt.Fprintf(w.output, "Storage settings:\n%s\nCredentials file: %s\n", raw, w.d.Credentials)
	if err := w.confirm("Check/configure existing cloud storage: write temporary test objects and attempt their removal; no bucket provisioning", "CONFIGURE STORAGE"); err != nil {
		return err
	}
	args := []string{"relay", "coordinator", "configure-storage", "--home", "/work/ceremony", "--coordinator-key", "/trust/setup-coordinator.hex", "--out", "/work/ceremony/config/relay-storage.json"}
	for _, field := range []string{"provider", "region", "published-bucket", "published-base-url", "inbox-bucket", "profile", "issuer-profile", "grant-role-arn", "grant-role-max-ttl", "account-id", "endpoint", "parent-access-key-id"} {
		if value := w.d.Storage[field]; value != "" {
			args = append(args, "--"+field, value)
		}
	}
	return w.action("storage", "coordinator", args, true)
}

func (w *coordinatorWizard) menu() (result error) {
	defer func() { result = errors.Join(result, w.cleanupSessionCredentials()) }()
	// Return cancellation through the owner so cleanup happens after any child
	// command has stopped, never concurrently with its credential mount.
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	stop, done := make(chan struct{}), make(chan struct{})
	w.interrupted = stop
	defer close(done)
	defer func() { w.interrupted = nil }()
	go func() {
		select {
		case <-signals:
			close(stop)
		case <-done:
		}
	}()
	if err := w.inspectPreviousSessionCredentials(); err != nil {
		return err
	}
	for {
		if w.d.Status == "draft" {
			fmt.Fprintf(w.output, "\nCoordinator preparation — %s (%s)\n1) Basics\n2) Generate my identity\n3) Import/replace public identity\n4) Orders, minimum contributions and reviewed beacon policy\n5) Supported computers (both architectures by default)\n6) Storage settings\n7) Review draft\n8) Approve and initialize\n9) Verify existing definition (also after interruption)\n10) Configure storage\n11) Remove an identity assignment\n0) Save and exit\n", w.d.Name, w.d.Status)
		} else {
			if w.d.Status == "definition-verified" {
				fmt.Fprintf(w.output, "\nInitialization complete — %s\nThe signed ceremony definition has been verified. Identities and policy are frozen.\nThis does not verify all initialization artifacts or start participant contributions.\n", w.d.Name)
				if w.localAction != nil {
					fmt.Fprintln(w.output, "Local setup test complete. Choose 0 to exit; your files are saved. This helper does not run contributions or configure cloud storage.")
				} else {
					fmt.Fprintln(w.output, "Next: distribute the signed public definition for assignment review, collect witness/mirror enrollments, and continue with the coordinator role guide. Storage can be configured below.")
				}
			} else {
				fmt.Fprintf(w.output, "\nInitialization needs verification — %s\nSettings are frozen after an initialization attempt. Preserve the files and error output; use 9 to verify an existing definition. Do not initialize again.\n", w.d.Name)
			}
			fmt.Fprintln(w.output, "7) Review identities and policy\n9) Verify existing definition")
			if w.localAction == nil && w.d.Status == "definition-verified" {
				fmt.Fprintln(w.output, "6) Storage settings\n10) Configure storage")
			}
			if w.d.Status == "definition-verified" {
				fmt.Fprintln(w.output, "12) Open ceremony operations and progress")
				if w.localAction == nil {
					fmt.Fprintln(w.output, "13) Prepare, review and sign MY coordinator enrollment")
				}
			}
			fmt.Fprintln(w.output, "0) Save and exit")
		}
		if w.localAction == nil {
			fmt.Fprintln(w.output, "14) Check storage access (writes and removes test objects only after approval)")
		}
		if w.d.Status == "draft" {
			fmt.Fprintln(w.output, "14 Open setup downloaded from Tessera")
		}
		if w.d.Status == "definition-verified" && (w.d.Tessera != nil || w.d.TesseraSetup != nil) && w.localAction == nil {
			fmt.Fprintln(w.output, "15 Export setup for Tessera")
		}
		choice, err := w.ask("Choose", "0")
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "0" {
			return w.save()
		}
		if w.d.Status != "draft" && (choice == "6" || choice == "10") && (w.localAction != nil || w.d.Status != "definition-verified") {
			fmt.Fprintln(w.output, "Storage setup is unavailable here. Choose one of the displayed actions.")
			continue
		}
		if w.d.Status != "draft" && (choice == "1" || choice == "2" || choice == "3" || choice == "4" || choice == "5" || choice == "8" || choice == "11") {
			fmt.Fprintln(w.output, "Ceremony draft frozen after initialization attempt. Do not edit signed settings or delete output to force a retry.")
			continue
		}
		switch choice {
		case "14":
			err = w.importTesseraRoster()
		case "15":
			err = w.exportTesseraSetup()
		case "13":
			if w.d.Status != "definition-verified" || w.localAction != nil {
				err = errors.New("coordinator enrollment requires the verified definition and approved release")
			} else {
				err = w.enrollCoordinator()
			}
		case "12":
			if w.d.Status != "definition-verified" {
				err = errors.New("verify the definition first")
			} else if w.continueFlow != nil {
				err = w.continueFlow()
			} else {
				err = w.openCoordinatorFlow()
			}
		case "1":
			err = w.basics()
		case "2":
			err = w.generateIdentity()
		case "3":
			err = w.identity()
		case "4":
			err = w.policy()
		case "5":
			err = w.binary()
		case "6":
			err = w.storage()
		case "7":
			w.summary()
			err = w.d.validate()
		case "8":
			err = w.prepareStorageBeforeInitialization()
			if err == nil {
				err = w.initialize()
			}
		case "14":
			err = w.checkStorage()
		case "9":
			err = w.verify()
		case "10":
			err = w.configureStorage()
		case "11":
			err = w.removeIdentity()
		default:
			err = errors.New("unknown option")
		}
		if err != nil {
			if errors.Is(err, errSecretPromptInterrupted) {
				return err
			}
			fmt.Fprintf(w.output, "Stopped: %v\nDraft retained. Review the error before retrying; never bypass verification.\n", err)
		}
	}
}

func runCoordinatorPrepare(args []string) error {
	var d coordinatorDraft
	flags := flag.NewFlagSet("coordinator prepare", flag.ContinueOnError)
	flags.StringVar(&d.Name, "name", "", "local ceremony name")
	flags.StringVar(&d.Release, "release", "", "exact approved role-images release")
	flags.StringVar(&d.Work, "work", "", "existing private work directory")
	flags.StringVar(&d.Trust, "trust", "", "existing public trust directory")
	flags.StringVar(&d.Keys, "keys", "", "existing private signing-key directory")
	flags.StringVar(&d.PolicyTemplate, "policy-template", "", "reviewed default initialization policy JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 || !guidedName.MatchString(d.Name) || !launcherReleaseTag.MatchString(d.Release) {
		return errors.New("valid --name and exact --release are required")
	}
	if err := checkLauncherRelease(strings.TrimPrefix(d.Release, "role-images-")); err != nil {
		return err
	}
	for _, path := range []string{d.Work, d.Trust, d.Keys} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("role directories must be absolute clean paths")
		}
		if _, err := os.Lstat(path); err != nil {
			return err
		}
		if err := ensurePrivateDirectory(path); err != nil {
			return err
		}
	}
	// Reuse the launcher mount validator, without starting Docker.
	if _, err := dockerRoleArgs(dockerRoleOptions{role: "coordinator", image: "sha256:" + strings.Repeat("0", 64), platform: "linux/amd64", work: d.Work, trust: d.Trust, keys: d.Keys}, []string{"mpc-ceremony", "version"}, os.Getuid(), os.Getgid()); err != nil {
		return err
	}
	st, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeCharDevice == 0 {
		return errors.New("coordinator preparation requires an interactive terminal")
	}
	root := filepath.Join(d.Work, "coordinator-setup")
	if err := ensurePrivateDirectory(root); err != nil {
		return err
	}
	path := filepath.Join(root, "draft.json")
	lock, err := acquireParticipantRunLock(path, root)
	if err != nil {
		return err
	}
	defer lock.release()
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("saved draft must be a private regular file")
		}
		var saved coordinatorDraft
		if err := setupReadJSON(path, &saved); err != nil {
			return err
		}
		if saved.Schema != "relay-coordinator-draft-v1" || saved.Name != d.Name || saved.Release != d.Release || saved.Work != d.Work || saved.Trust != d.Trust || saved.Keys != d.Keys {
			return errors.New("saved draft differs from selected release/name/directories; use its original settings")
		}
		if saved.Status != "draft" && saved.Status != "initialization-attempted" && saved.Status != "definition-verified" {
			return errors.New("unknown draft status")
		}
		d = saved
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		d.Schema = "relay-coordinator-draft-v1"
		d.Status = "draft"
		d.Storage = map[string]string{}
		if err := saveCoordinatorDraft(path, d); err != nil {
			return err
		}
	}
	w := coordinatorWizard{d: d, input: bufio.NewReader(os.Stdin), output: os.Stdout, draftPath: path, run: executeGuidedChild}
	w.prepareBinaries = w.prepareApprovedArchitectures
	return w.menu()
}
