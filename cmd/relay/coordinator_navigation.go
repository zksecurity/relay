package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Recommendations are navigation only. Existing actions still authenticate,
// validate, ask for consent, and freeze the draft at the initialization boundary.
type preparationNext struct{ choice, label, reason string }

func (w *coordinatorWizard) nextPreparationAction() preparationNext {
	d := w.d
	if d.Status != "draft" {
		if d.Status != "definition-verified" {
			return preparationNext{"9", "Verify existing definition (recover an interrupted initialization)", "Required: recovery procedure. Settings are frozen; do not initialize again."}
		}
		if w.localAction != nil {
			return preparationNext{"0", "Save and exit", "Local setup test complete. No contributions or cloud setup were performed."}
		}
		for _, name := range []string{"canonical.json", "enrollment.sig"} {
			if info, err := os.Lstat(filepath.Join(d.Work, "my-enrollment", name)); err != nil || !info.Mode().IsRegular() {
				return preparationNext{"13", "Prepare, review and sign MY coordinator enrollment", "Required: role procedure. This binds your key to the signed assignment; it does not establish independent people. Existing output is reviewed before reuse."}
			}
		}
		return preparationNext{"12", "Open ceremony operations and progress", "Required: role procedure. Enrollment files are present, not verified by this menu. Operations recheck the relevant evidence."}
	}
	if (d.Mode != "rehearsal" && d.Mode != "production") || (d.Circuit != "ownership-destination-v2" && !(d.Mode == "rehearsal" && d.Circuit == "rehearsal-tiny-v1")) {
		return preparationNext{"1", "Basics: choose ceremony mode and circuit", "Required: signed ceremony definition."}
	}
	if d.Identities.Coordinator.check() != nil {
		for _, name := range []string{"identity.json", "signing.hex"} {
			if _, err := os.Lstat(filepath.Join(d.Keys, name)); !os.IsNotExist(err) {
				return preparationNext{"3", "Import or recover your existing coordinator identity", "Required: signing identity. Key output already exists or cannot be inspected; preserve it rather than generate over it."}
			}
		}
		return preparationNext{"2", "Generate MY coordinator identity", "Required: your own signing identity. Other roles provide their public identity files."}
	}
	ids := []setupIdentity{d.Identities.Coordinator, d.Identities.ReleaseSigner}
	ids = append(ids, d.Identities.Auditors...)
	for _, p := range d.Identities.Roster {
		ids = append(ids, p.Identity)
	}
	seenID, seenKey, seenPub := map[string]bool{}, map[string]bool{}, map[string]bool{}
	rosterReady := len(d.Identities.Auditors) >= 2 && len(d.Identities.Roster) > 0
	for _, id := range ids {
		if id.check() != nil || seenID[id.ID] || seenKey[id.KeyID] || seenPub[id.Fingerprint] {
			rosterReady = false
		}
		seenID[id.ID], seenKey[id.KeyID], seenPub[id.Fingerprint] = true, true, true
	}
	if !rosterReady {
		return preparationNext{"3", "Import or correct the required public identities", "Required: coordinator, final-parameter signer, at least two auditors and one participant, with distinct keys. Witness/mirror enrollments come after initialization."}
	}
	if d.ArchitecturePolicy != "" && d.ArchitecturePolicy != "both" && d.ArchitecturePolicy != "single" && d.ArchitecturePolicy != "custom" {
		return preparationNext{"5", "Review supported computers", "Required: correct the saved architecture selection. Both architectures are the default."}
	}
	if err := d.validate(); err != nil {
		return preparationNext{"4", "Review participant orders, minimums and beacon policy", "Required: signed ceremony policy. " + err.Error()}
	}
	if w.localAction == nil && !d.OfflinePreparation {
		s := coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", d.Storage}
		if _, err := s.infrastructure(); err != nil || d.Credentials == "" || (d.Storage["provider"] == "r2" && (d.R2Parent == "" || d.R2Control == "")) {
			return preparationNext{"6", "Set up storage and protected credentials", "Required for online operation: Relay procedure, not cryptography. Explicit offline preparation is available under other actions."}
		}
	}
	label := "Check storage, review and approve initialization"
	if w.localAction != nil || d.OfflinePreparation {
		label = "Review and approve initialization"
	}
	return preparationNext{"8", label, "Required: explicit approval. Saved settings are not proof of live storage access. Initialization revalidates inputs and asks before signing."}
}

func (w *coordinatorWizard) preparationHeading(next preparationNext) {
	w.message(toneHeading, "\nRELAY | COORDINATOR | %s\n------------------------------------------------------------\n", w.d.Name)
	switch w.d.Status {
	case "draft":
		fmt.Fprintln(w.output, "Ceremony setup — unsigned draft")
	case "definition-verified":
		w.message(toneSuccess, "Initialization complete — last definition verification succeeded.\n")
		fmt.Fprintln(w.output, "Identities and policy are frozen. This is not verification of all artifacts or current storage access.")
	default:
		fmt.Fprintln(w.output, "Initialization needs verification — preserve existing output.")
	}
	heading := "NEXT REQUIRED ACTION"
	if next.choice == "0" {
		heading = "SETUP CHECKPOINT"
	}
	w.message(toneHeading, "\n%s\n  %s\n", heading, next.label)
	w.message(toneMuted, "  %s\n", next.reason)
}
