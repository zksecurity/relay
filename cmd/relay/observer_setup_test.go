package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/transcript"
)

func observerFixture(t *testing.T, role string) observerSetup {
	w := setupFixture(t)
	w.d.Identities.Coordinator.ID = role + "-" + w.d.Identities.Coordinator.Fingerprint[7:15]
	w.d.Identities.Coordinator.KeyID = "ed25519:" + w.d.Identities.Coordinator.Fingerprint[7:]
	return observerSetup{"relay-observer-setup-v1", "ceremony", strings.Repeat("a", 64), role, 1, w.d.Identities.Coordinator}
}

func observerTestJourney() *transcript.DefinitionJourney {
	j := &transcript.DefinitionJourney{Schema: "proof-tool-mpc-definition-journey-v1", MinimumPublicWitnesses: 1, MinimumMirrorsPerAcceptedHead: 1, ObserverRequirementSource: "test verified requirements"}
	for n, role := range []string{"coordinator", "release-signer", "auditor", "participant"} {
		id := transcript.PublicIdentity{ID: role, KeyID: "key-" + role, PublicKeyFingerprint: "sha256:" + strings.Repeat(string(rune('a'+n)), 64)}
		j.RequiredEnrollments = append(j.RequiredEnrollments, transcript.ExpectedEnrollment{Role: role, RoleIndex: 1, Identity: id})
	}
	return j
}

func TestObserverReservationsStableAndDistinct(t *testing.T) {
	root := filepath.Join(t.TempDir(), "reservations")
	a := observerFixture(t, "witness")
	path, err := reserveObserverSetup(root, a, nil)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	again, err := reserveObserverSetup(root, a, nil)
	if err != nil || again != path {
		t.Fatal(again, err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("reservation changed")
	}
	b := observerFixture(t, "witness")
	b.Identity.ID = "second"
	path, err = reserveObserverSetup(root, b, nil)
	if err != nil || filepath.Base(path) != "witness-2.json" {
		t.Fatal(path, err)
	}
	c := observerFixture(t, "mirror")
	c.Identity.ID = "mirror"
	path, err = reserveObserverSetup(root, c, nil)
	if err != nil || filepath.Base(path) != "mirror-1.json" {
		t.Fatal(path, err)
	}
	a.Role = "mirror"
	if _, err := reserveObserverSetup(root, a, nil); err == nil {
		t.Fatal("identity reused in another role")
	}
}

func TestObserverReservationFailsClosed(t *testing.T) {
	for _, scenario := range []string{"malformed", "interrupted", "locked", "other-ceremony", "occupied"} {
		t.Run(scenario, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "reservations")
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			s := observerFixture(t, "witness")
			var occupied []observerSetup
			switch scenario {
			case "malformed":
				if err := os.WriteFile(filepath.Join(root, "witness-1.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "interrupted":
				if err := os.WriteFile(filepath.Join(root, ".public-import-test"), []byte("partial"), 0600); err != nil {
					t.Fatal(err)
				}
			case "locked":
				lock, err := acquireParticipantRunLock("", root)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.release()
			case "other-ceremony":
				old := s
				old.CeremonyID = "other"
				occupied = []observerSetup{old}
			case "occupied":
				old := s
				old.Identity.DisplayName = "conflicting identity"
				occupied = []observerSetup{old}
			}
			if _, err := reserveObserverSetup(root, s, occupied); err == nil {
				t.Fatal("unsafe allocation")
			}
		})
	}
}

func TestObserverSetupImportAndAutomaticNumber(t *testing.T) {
	p := preparationFixture(t, "witness")
	s := observerFixture(t, "witness")
	s.Index = 2
	if err := writeJSONNoReplace(filepath.Join(p.d.Keys, "identity.json"), s.Identity, 0600); err != nil {
		t.Fatal(err)
	}
	def := filepath.Join(p.d.Work, "ceremony/public/ceremony.json")
	if err := os.WriteFile(def, []byte("public definition fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	s.DefinitionSHA256, _ = setupFileHash(def)
	p.inspectDefinition = func() (transcript.Definition, error) {
		return transcript.Definition{CeremonyID: s.CeremonyID, Journey: observerTestJourney()}, nil
	}
	source := filepath.Join(p.d.Work, "received-setup.json")
	if err := writeJSONNoReplace(source, s, 0600); err != nil {
		t.Fatal(err)
	}
	p.ui.input = bufio.NewReader(strings.NewReader("9\n" + source + "\nREVIEWED\n"))
	if err := p.importFile(); err != nil {
		t.Fatal(err)
	}
	index, err := p.observerEnrollmentIndex()
	if err != nil || index != "2" {
		t.Fatal(index, err)
	}
	for _, change := range []func(*observerSetup){
		func(s *observerSetup) { s.Role = "mirror" }, func(s *observerSetup) { s.CeremonyID = "other" }, func(s *observerSetup) { s.DefinitionSHA256 = strings.Repeat("b", 64) }, func(s *observerSetup) { s.Identity.ID = "other" }, func(s *observerSetup) { s.Index = 0 }, func(s *observerSetup) { s.Index = 65536 },
	} {
		bad := s
		change(&bad)
		if err := p.checkObserverSetup(bad); err == nil {
			t.Fatal("accepted conflicting setup")
		}
	}
	p.d.Values["enrollment-index"] = "1"
	if err := p.checkObserverSetup(s); err == nil {
		t.Fatal("overrode saved number")
	}
	delete(p.d.Values, "enrollment-index")
	raw, _ := json.Marshal(s)
	if len(raw) == 0 {
		t.Fatal("empty setup")
	}
}

func TestLegacyObserverNumberRemainsUsable(t *testing.T) {
	p := preparationFixture(t, "mirror")
	p.d.Values["enrollment-index"] = "2"
	index, err := p.observerEnrollmentIndex()
	if err != nil || index != "2" {
		t.Fatal(index, err)
	}
	p.d.Values["enrollment-index"] = "65536"
	if _, err := p.observerEnrollmentIndex(); err == nil {
		t.Fatal("invalid legacy index accepted")
	}
}

func TestExistingObserverEnrollmentResumesWithoutSetupFile(t *testing.T) {
	p := preparationFixture(t, "witness")
	prepareTestProfile(t, p, "decision-signer")
	s := observerFixture(t, "witness")
	if err := writeJSONNoReplace(filepath.Join(p.d.Keys, "identity.json"), s.Identity, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(p.d.Work, "my-enrollment")
	disclosure := filepath.Join(dir, "enrollments", s.Identity.ID, "disclosure.txt")
	if err := os.MkdirAll(filepath.Dir(disclosure), 0700); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"ceremony_id": s.CeremonyID, "identity": s.Identity, "role": "public-witness", "role_index": 2})
	for path, content := range map[string][]byte{filepath.Join(dir, "canonical.json"): raw, filepath.Join(dir, "enrollment.sig"): []byte("test signature"), disclosure: []byte("test disclosure")} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	verified := false
	p.run = func(args []string) error {
		if !strings.Contains(strings.Join(args, " "), "mpc-ceremony inspect enrollment") {
			t.Fatal("existing enrollment was reprepared or signed", args)
		}
		verified = true
		return nil
	}
	p.ui.input = bufio.NewReader(strings.NewReader("REVIEWED\n"))
	if err := p.enroll(); err != nil {
		t.Fatal(err)
	}
	if !verified || bytes.Contains(p.ui.output.(*bytes.Buffer).Bytes(), []byte("Path to the observer setup")) {
		t.Fatal("legacy resume required new assignment")
	}
}

func TestCoordinatorToObserverSetupHandoff(t *testing.T) {
	for _, role := range []string{"witness", "mirror"} {
		t.Run(role, func(t *testing.T) {
			w := setupFixture(t)
			root := filepath.Join(w.d.Work, "ceremony/public")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			definitionBytes := []byte("synthetic public definition; inspector mocked")
			if err := os.WriteFile(filepath.Join(root, "ceremony.json"), definitionBytes, 0600); err != nil {
				t.Fatal(err)
			}
			d := transcript.Definition{CeremonyID: "ceremony", Journey: observerTestJourney()}
			// Use the real fixed roster identities so observer-key conflicts remain
			// covered while the signed policy keeps observers post-initialization.
			d.Journey.RequiredEnrollments = nil
			for _, fixed := range []struct {
				role     string
				identity setupIdentity
			}{{"coordinator", w.d.Identities.Coordinator}, {"release-signer", w.d.Identities.ReleaseSigner}, {"auditor", w.d.Identities.Auditors[0]}, {"participant", w.d.Identities.Roster[0].Identity}} {
				raw, _ := json.Marshal(fixed.identity)
				var id transcript.PublicIdentity
				if err := json.Unmarshal(raw, &id); err != nil {
					t.Fatal(err)
				}
				d.Journey.RequiredEnrollments = append(d.Journey.RequiredEnrollments, transcript.ExpectedEnrollment{Role: fixed.role, RoleIndex: 1, Identity: id})
			}
			s := observerFixture(t, role)
			identityPath := filepath.Join(root, "observer-identity.json")
			if err := writeJSONNoReplace(identityPath, s.Identity, 0600); err != nil {
				t.Fatal(err)
			}
			choice := "1"
			if role == "mirror" {
				choice = "2"
			}
			f := roleFlow{state: roleFlowState{Profile: guidedProfile{Work: w.d.Work}}, ui: coordinatorWizard{input: bufio.NewReader(strings.NewReader(choice + "\n" + identityPath + "\nVERIFIED\n")), output: new(bytes.Buffer)}, definition: func() (transcript.Definition, error) { return d, nil }}
			if err := f.prepareObserverSetup(); err != nil {
				t.Fatal(err)
			}
			issued := filepath.Join(root, "observer-setups", role+"-1.json")
			p := preparationFixture(t, role)
			if err := writeJSONNoReplace(filepath.Join(p.d.Keys, "identity.json"), s.Identity, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p.d.Work, "ceremony/public/ceremony.json"), definitionBytes, 0600); err != nil {
				t.Fatal(err)
			}
			p.inspectDefinition = func() (transcript.Definition, error) { return d, nil }
			p.ui.input = bufio.NewReader(strings.NewReader("9\n" + issued + "\nREVIEWED\n"))
			if err := p.importFile(); err != nil {
				t.Fatal(err)
			}
			index, err := p.observerEnrollmentIndex()
			if err != nil || index != "1" {
				t.Fatal(index, err)
			}
			if _, err := os.Stat(filepath.Join(p.d.Work, "my-enrollment/canonical.json")); !os.IsNotExist(err) {
				t.Fatal("setup falsely created enrollment")
			}
		})
	}
}
