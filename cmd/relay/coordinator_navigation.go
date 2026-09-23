package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Recommendations are navigation only. Existing actions still authenticate,
// validate, ask for consent, and freeze the draft at the initialization boundary.
type preparationNext struct{ choice, label, reason string }

// An allowed alternative is not the recommended next action. These choices
// follow a sufficient roster; imported website assignments remain website-owned.
func (w *coordinatorWizard) showOptionalIdentityImport(next preparationNext) bool {
	if w.d.Status != "draft" || w.d.Tessera != nil || w.d.TesseraSetup != nil || w.d.TesseraSetupV3 != nil {
		return false
	}
	switch next.choice {
	case "4", "5", "6", "8":
		return true
	default:
		return false
	}
}

func (w *coordinatorWizard) nextPreparationAction() preparationNext {
	d := w.d
	if d.Status != "draft" {
		if d.Status == "initialization-attempted" {
			return preparationNext{"8", "Resume and verify the exact frozen initialization", "Relay reuses the saved time, nonce, identities and policy. Existing files must match and are never overwritten."}
		}
		if d.Status != "definition-verified" {
			return preparationNext{"9", "Verify existing definition", "Authenticate the retained signed definition before continuing."}
		}
		if w.localAction != nil {
			return preparationNext{"0", "Save and exit", "Local setup test complete. No contributions or cloud setup were performed."}
		}
		for _, name := range []string{"canonical.json", "enrollment.sig"} {
			if info, err := os.Lstat(filepath.Join(d.Work, "my-enrollment", name)); err != nil || !info.Mode().IsRegular() {
				return preparationNext{"13", "Prepare, review and sign MY coordinator enrollment", "Bind your key to the signed coordinator assignment. This proves key control, not independent people. Existing output is reviewed before reuse."}
			}
		}
		if w.d.Tessera != nil || w.d.TesseraSetup != nil || w.d.TesseraSetupV3 != nil {
			if w.tesseraExportPresent() {
				return preparationNext{"0", "Save and exit — return to Tessera", "Setup exported. Upload it to Tessera, review and lock the setup. Export is not proof of website acceptance. Export again or explicitly continue to operations below."}
			}
			return preparationNext{"16", "Export setup for Tessera", "Export the completed setup, then upload it to Tessera for review and locking. Enrollment files are present; operations reverify their evidence."}
		}
		if !regularPreparationFile(filepath.Join(d.Work, "ceremony/config/relay-storage.json")) && !d.OfflinePreparation {
			return preparationNext{"10", "Create the public storage configuration for ceremony roles", "Configure storage to create relay-storage.json. Online roles need this public file before profile creation; infrastructure settings and credentials are not its replacement."}
		}
		return preparationNext{"12", "Open ceremony operations and progress", "Continue with the coordinator workflow. Enrollment files are present but this menu has not verified them; operations recheck the relevant evidence."}
	}
	if (d.Mode != "rehearsal" && d.Mode != "production") || !supportedCeremonyCircuit(d.Circuit) {
		return preparationNext{"1", "Basics: choose ceremony mode and circuit", "A signed definition must identify the ceremony mode and circuit."}
	}
	if d.Identities.Coordinator.check() != nil {
		for _, name := range []string{"identity.json", "signing.hex"} {
			if _, err := os.Lstat(filepath.Join(d.Keys, name)); !os.IsNotExist(err) {
				return preparationNext{"3", "Import or recover your existing coordinator identity", "Use your existing coordinator signing identity. A key output already exists or cannot be inspected, so Relay will not generate over it."}
			}
		}
		return preparationNext{"2", "Generate MY coordinator identity", "Create the signing identity for your coordinator role. Other roles provide their own public identity files."}
	}
	ids := []setupIdentity{d.Identities.Coordinator, d.Identities.ReleaseSigner}
	ids = append(ids, d.Identities.Auditors...)
	for _, p := range d.Identities.Roster {
		ids = append(ids, p.Identity)
	}
	seenID, seenKey, seenPub := map[string]bool{}, map[string]bool{}, map[string]bool{}
	rosterReady := len(d.Identities.Roster) > 0
	for _, id := range ids {
		if id.check() != nil || seenID[id.ID] || seenKey[id.KeyID] || seenPub[id.Fingerprint] {
			rosterReady = false
		}
		seenID[id.ID], seenKey[id.KeyID], seenPub[id.Fingerprint] = true, true, true
	}
	if !rosterReady {
		return preparationNext{"3", "Import or correct the required public identities", "The definition needs a coordinator, final signer and at least one participant with distinct keys. Add auditors only when the assurance policy will require ceremony audits; witnesses and mirrors enroll after initialization."}
	}
	if d.ArchitecturePolicy != "" && d.ArchitecturePolicy != "both" && d.ArchitecturePolicy != "single" && d.ArchitecturePolicy != "custom" {
		return preparationNext{"5", "Review supported computers", "Correct the saved architecture selection. Both supported Linux architectures are selected by default."}
	}
	if err := d.validate(); err != nil {
		return preparationNext{"4", "Review participant orders, minimums and beacon policy", "The signed definition needs a valid participant order, contribution minimum, and beacon policy. " + err.Error()}
	}
	if w.localAction == nil && !d.OfflinePreparation {
		s := coordinatorStorageSettings{"relay-coordinator-storage-settings-v1", d.Storage}
		if _, err := s.infrastructure(); err != nil || d.Credentials == "" || (d.Storage["provider"] == "r2" && (d.R2Parent == "" || d.R2Control == "")) {
			return preparationNext{"6", "Set up storage and protected credentials", "Online operations need verified storage settings and protected credentials. This is Relay safety workflow, not a cryptographic requirement. Explicit offline preparation is available under other actions."}
		}
	}
	label := "Check storage, review and approve initialization"
	if w.localAction != nil || d.OfflinePreparation {
		label = "Review and approve initialization"
	}
	return preparationNext{"8", label, "Freeze the reviewed settings into the signed definition. Saved settings do not prove live storage access; initialization rechecks inputs and asks before signing."}
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
	if next.choice == "16" || (next.choice == "0" && w.tesseraExportPresent()) {
		heading = "NEXT STEP — RETURN TO TESSERA"
	} else if next.choice == "0" {
		heading = "SETUP CHECKPOINT"
	}
	w.message(toneHeading, "\n%s\n  %s\n\nWHY THIS STEP IS NEEDED\n", heading, next.label)
	w.message(toneMuted, "  %s\n", next.reason)
}
