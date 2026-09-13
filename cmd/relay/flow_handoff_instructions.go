package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/zksecurity/relay/internal/transcript"
)

type handoffInstruction struct {
	counterpart, next string
	// Additional public directories are transfer instructions, not evidence
	// completeness assertions. Individual bindings still use handoffFields.
	directories []string
}

func handoffInstructionFor(id string) (handoffInstruction, bool) {
	all := map[string]handoffInstruction{
		"assignments":                 {"Every assigned role, including witnesses and mirrors", "Ask each role to return its signed public enrollment folder; verify it in Enrollment collection.", nil},
		"assignment":                  {"Your coordinator", "Send only identity.json from your keys folder; receive and independently review the signed ceremony set and your assignment. Never send signing.hex.", nil},
		"storage":                     {"Online roles: participants, witnesses, mirrors, auditors and upload station", "Recipients import this as Public storage configuration. Do not send cloud credentials or grants with it.", nil},
		"deliver-input":               {"The participant named in the current signed handoff", "Send the packet and every listed payload. The participant stages payloads at the same relative paths under its received-files root, prepares and signs the outbound receipt, and returns canonical.json plus record.sig. Verify that receipt before issuing the grant.", nil},
		"deliver-input-receipt":       {"Your coordinator", "Return both receipt files. The coordinator verifies them against the original handoff; wait for the private grant and authorization before contributing.", nil},
		"deliver-output":              {"Your coordinator", "Send the return packet and every listed public candidate file. Preserve their relative paths. The coordinator prepares and signs the return receipt before accepting the candidate.", nil},
		"turns-complete":              {"Your coordinator records and the scheduled participants", "No new file transfer is requested here. Recheck the authenticated accepted head against the schedule before closing.", nil},
		"witnesses-ready":             {"Every required witness", "No file transfer is requested here. Obtain readiness confirmation through the agreed channel before closing; confirmation is not an observation receipt.", nil},
		"observations":                {"Enrolled witnesses and beacon-relay operators", "Request each signed observation receipt and the distinct relay responses for this exact closure and committed round. Keep original relative paths in the public evidence tree; the next verification checks them.", []string{"/work/ceremony/public"}},
		"public-proof":                {"The circuit's public-evidence generator", "Give only the public preliminary bundle; request the public proof artifact consumed by Complete finalization. Do not exchange private application inputs.", []string{"/work/preliminary"}},
		"audits":                      {"Each enrolled auditor", "Send the complete public candidate and transcript, including Phase 1 seal. Auditors stage candidate under /work/candidate and transcript under /work/ceremony/public, then return their signed audit report and signature.", []string{"/work/candidate", "/work/ceremony/public"}},
		"signer":                      {"Your final-parameter signer", "Send the complete candidate, all selected audit report/signature pairs and signed operational bundle with its referenced public evidence tree. Use the agreed offline transfer procedure. Request the complete signed public release; never request a private key.", []string{"/work/candidate", "/work/ceremony/public"}},
		"archive":                     {"Required mirrors and accountable roles", "Retain the complete verified public archive and evidence under the agreed retention plan. Confirm required authorization separately; a report here is not archive verification.", []string{"/work/release", "/work/ceremony/public"}},
		"accepted":                    {"Your coordinator", "Ask for independently verifiable acceptance of this exact submission. An upload or notification is not acceptance; this step does not send additional files.", nil},
		"retain":                      {"Your coordinator and agreed archive custodians", "Agree where the public archive will be retained and how to report loss. Do not transfer the whole role workspace or private signing material.", nil},
		"reconnect":                   {"Your online upload action (same role)", "Keep canonical.json and receipt.sig together in the public receipt directory. Run Upload signed PUBLIC output next. Do not move your private key to the online environment.", nil},
		"offline":                     {"The final signer operating this machine", "No file transfer is requested. Disconnect the signing host after public inputs and approved images are prepared; Docker network isolation alone is not host disconnection.", nil},
		"handoff":                     {"Your upload station", "Send the complete signed public release directory, preserving names. The upload station stages it at /work/release, verifies it and uploads it; your private key remains offline.", []string{"/work/release"}},
		"receive-release":             {"Your final-parameter signer", "Request the complete signed public release and stage it in the locations below. Obtain the signer public key independently; run release verification before upload.", []string{"/work/release"}},
		"receive-audit-inputs":        {"Your coordinator and independently checked mirrors", "Request the complete candidate and transcript, including Phase 1 seal. Stage them below or select the actual paths in the audit command. Receipt of files is not verification.", []string{"/work/candidate", "/work/ceremony/public"}},
		"receive-signing-inputs":      {"Your coordinator", "Request candidate, each audit report/signature pair, and the operational bundle plus its complete evidence tree. Transfer to the offline host without reconnecting it. Keep audit pairs separately named and select them in final signing.", []string{"/work/candidate", "/work/ceremony/public"}},
		"collect-submissions":         {"Each role with outstanding public evidence", "Request its upload manifest location or public evidence folder. Use List submitted evidence and Download submitted evidence; preserve relative paths when assembling the public tree below.", []string{"/work/ceremony/public"}},
		"receive-decision":            {"Your coordinator", "Request the exact canonical decision and complete decision-evidence tree. Stage them below; review and sign only after verification.", []string{"/work/decision-evidence"}},
		"deliver-decision":            {"Every required auditor and final signer", "Send the canonical decision and complete referenced decision-evidence tree; recipients stage decision.json and decision-evidence under /work and return only their detached signature.", []string{"/work/decision-evidence"}},
		"collect-decision-signatures": {"Every required accountable signer", "Request signatures for the exact decision shown below. Keep each signature at a distinct public filename; select all required signatures in Verify decision.", nil},
		"return-decision-signature":   {"Your coordinator", "Send the detached signature below and identify its exact canonical decision. The coordinator verifies the required signature set; keep your signing key private.", nil},
		"decision-scope":              {"Your coordinator and accountable roles", "No new file transfer is requested. Retain the verified production decision and required signatures, or the authenticated rehearsal applicability result.", nil},
		"notify-submission":           {"Your coordinator", "Send the exact manifest location from Upload signed PUBLIC output. For Tessera, confirm the automatic notification succeeded; do not invent a location or resend credentials. Use the upload's recovery action if notification failed.", nil},
		"deliver-grant":               {"Only the named participant", "Use the private-grant delivery summary showing the exact file, recipient and expiry. Never publish it.", nil},
		"deliver-evidence-grant":      {"Only the named evidence owner", "Use the private-grant delivery summary showing the exact file, recipient and expiry. Never publish it.", nil},
	}
	i, ok := all[id]
	return i, ok
}

func custodyDeliveryTask(id string) bool {
	return id == "deliver-input" || id == "deliver-input-receipt" || id == "deliver-output"
}

// Resolve authored public locations through the actual saved command inputs or
// outputs. This is a location hint, not a new verification result.
func (f *roleFlow) savedPublicHandoffPath(path string) string {
	seen := map[string]bool{}
	for n := len(f.state.Attempts) - 1; n >= 0; n-- {
		a := f.state.Attempts[n]
		key := a.Stage + "/" + a.Task
		if seen[key] {
			continue
		}
		seen[key] = true
		if a.Status != "succeeded" {
			continue
		}
		if a.TurnScope != nil && !reflect.DeepEqual(a.TurnScope, f.turnScope) {
			continue
		}
		for _, stage := range f.stages {
			if stage.ID != a.Stage {
				continue
			}
			for _, task := range stage.Tasks {
				if task.ID != a.Task {
					continue
				}
				for _, field := range task.Fields {
					if field.Kind != "path" || !strings.HasPrefix(field.Default, "/work/") {
						continue
					}
					if path != field.Default && !strings.HasPrefix(path, field.Default+"/") {
						continue
					}
					actual := commandValue(a.Command, field.Flag)
					if strings.HasPrefix(actual, "/work/") {
						return actual + strings.TrimPrefix(path, field.Default)
					}
				}
			}
		}
	}
	return f.rememberedOutputPath(path, true)
}

// Select the latest operation for this exact scope, including failed attempts.
// Never fall back to an older success or another participant's turn.
func (f *roleFlow) deliveryProducer(id string) (*flowAttempt, error) {
	for n := len(f.state.Attempts) - 1; n >= 0; n-- {
		a := &f.state.Attempts[n]
		if a.Task != id || a.Stage != f.stages[f.state.Stage].ID || !reflect.DeepEqual(a.TurnScope, f.turnScope) {
			continue
		}
		if a.Status != "succeeded" {
			return nil, fmt.Errorf("complete or resolve %s for this turn first", id)
		}
		if err := f.checkAttemptEvidence(a); err != nil {
			return nil, err
		}
		return a, nil
	}
	return nil, fmt.Errorf("no completed %s for this turn; open that preparation/signing action first", id)
}

func (f *roleFlow) custodyDeliveryFields(task flowTask, expected ...map[string]string) ([]flowField, string, error) {
	direction, kind := "outbound", "handoff"
	if task.ID == "deliver-output" {
		direction = "return"
	}
	if task.ID == "deliver-input-receipt" {
		kind = "receipt"
	}
	sign, err := f.deliveryProducer("sign-" + direction + "-" + kind)
	if err != nil {
		return nil, "", err
	}
	prepare, err := f.deliveryProducer("prepare-" + direction + "-" + kind)
	if err != nil {
		return nil, "", err
	}
	record, signature := commandValue(sign.Command, "record"), commandValue(sign.Command, "out")
	if record == "" || signature == "" || flowHostPath(f.state.Profile, record) != filepath.Join(flowHostPath(f.state.Profile, commandValue(prepare.Command, "out-dir")), "canonical.json") {
		return nil, "", errors.New("saved signing record does not match this turn's preparation output; inspect the packet")
	}
	fields := []flowField{ff("record", "Canonical public "+kind, record), ff("record", "Detached public signature", signature)}
	// Bind the displayed snapshot, not a later independently captured baseline.
	bindings := map[string]string{}
	for _, field := range fields {
		local, err := f.publicHostPath(field.Default)
		if err != nil {
			return nil, "", err
		}
		hash, err := setupFileHash(local)
		if err != nil {
			return nil, "", err
		}
		bindings[field.Default] = hash
	}
	if saved := sign.InputBindings[record]; saved != "" && saved != bindings[record] {
		return nil, "", errors.New("canonical record changed since signing")
	}
	if len(expected) > 0 {
		for path, hash := range bindings {
			expected[0][path] = hash
		}
	}
	if kind == "receipt" {
		return fields, "coordinator", nil
	}
	local, err := f.publicHostPath(record)
	if err != nil {
		return nil, "", err
	}
	raw, err := readPreparationInput(local)
	if err != nil {
		return nil, "", err
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != bindings[record] {
		return nil, "", errors.New("handoff changed while preparing delivery instructions")
	}
	var packet struct {
		Recipient string                   `json:"recipient_id"`
		Files     []transcript.ArtifactRef `json:"files"`
	}
	if err := json.Unmarshal(raw, &packet); err != nil || len(packet.Files) == 0 || len(packet.Files) > 1024 || packet.Recipient == "" {
		return nil, "", errors.New("invalid retained public handoff; inspect the signed packet")
	}
	root := commandValue(prepare.Command, "transcript-root")
	if root == "" {
		return nil, "", errors.New("saved handoff has no public payload root")
	}
	seen := map[string]bool{}
	for _, ref := range packet.Files {
		name := ref.Name
		if !filepath.IsLocal(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.ContainsAny(name, "\\\r\n\x1b") || seen[name] {
			return nil, "", errors.New("unsafe or duplicate handoff payload path")
		}
		seen[name] = true
		path := strings.TrimSuffix(root, "/") + "/" + name
		local, err := f.publicHostPath(path)
		if err != nil {
			return nil, "", err
		}
		st, err := os.Lstat(local)
		if err != nil || !st.Mode().IsRegular() || st.Size() != ref.Digest.Size {
			return nil, "", fmt.Errorf("missing or changed payload %q; restore the exact file named by the handoff", name)
		}
		digest, err := setupFileHash(local)
		if err != nil || "sha256:"+digest != ref.Digest.SHA256 {
			return nil, "", fmt.Errorf("payload %q does not match the handoff digest", name)
		}
		fields = append(fields, ff("record", "Public payload (keep relative path "+name+")", path))
		if len(expected) > 0 {
			expected[0][path] = digest
		}
	}
	return fields, packet.Recipient, nil
}

func (f *roleFlow) showHandoffInstructions(task flowTask, expected ...map[string]string) ([]flowField, error) {
	i, ok := handoffInstructionFor(task.ID)
	if !ok {
		return nil, errors.New("handoff instructions unavailable; contact the coordinator")
	}
	fmt.Fprintf(f.ui.output, "\nHANDOFF DETAILS\nWith: %s\n%s\n", i.counterpart, i.next)
	fields := f.handoffFields(task)
	var resolveErr error
	if custodyDeliveryTask(task.ID) {
		var recipient string
		fields, recipient, resolveErr = f.custodyDeliveryFields(task, expected...)
		if recipient != "" {
			fmt.Fprintf(f.ui.output, "Recipient named by the retained packet: %q\n", recipient)
		}
	}
	for _, field := range fields {
		fmt.Fprintf(f.ui.output, "  %s: %s\n", field.Label, flowHostPath(f.state.Profile, field.Default))
	}
	for _, dir := range i.directories {
		fmt.Fprintf(f.ui.output, "  Public directory location (confirm against your saved action): %s\n", flowHostPath(f.state.Profile, f.savedPublicHandoffPath(dir)))
	}
	if task.ID == "assignment" {
		fmt.Fprintf(f.ui.output, "  Your public identity only: %s\n", filepath.Join(f.state.Profile.Keys, "identity.json"))
	}
	fmt.Fprintln(f.ui.output, "Receiver /work paths are staging instructions, not paths measured on their machine. Use your agreed transfer channel. Never send the whole role folder, signing keys or cloud credentials. A report is not verified delivery or acceptance.")
	if resolveErr != nil {
		fmt.Fprintf(f.ui.output, "Not ready to report delivery: %v\n", resolveErr)
	}
	return fields, resolveErr
}
