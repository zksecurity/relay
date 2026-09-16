package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

func (f *roleFlow) inspectionContext() (transcript.Inspector, []string, error) {
	p := f.state.Profile
	if p.Work == "" {
		return transcript.Inspector{}, nil, errors.New("signed definition has not been supplied")
	}
	key := f.state.Values["shared/coordinator-public-key-file"]
	if key == "" {
		key = "/trust/coordinator-public-key.hex"
	}
	command := []string{"--ceremony", "/work/ceremony/public/ceremony.json", "--ceremony-signature", "/work/ceremony/public/ceremony.sig", "--coordinator-public-key-file", key}
	if err := f.bindPublicInputs(command); err != nil {
		return transcript.Inspector{}, nil, err
	}
	hostKey, err := f.publicHostPath(key)
	if err != nil {
		return transcript.Inspector{}, nil, err
	}
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		return transcript.Inspector{}, nil, err
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		return transcript.Inspector{}, nil, err
	}
	if err := prepareGuidedImage(p.Image, p.Platform, "docker", false); err != nil {
		return transcript.Inspector{}, nil, err
	}
	root := filepath.Join(p.Work, "ceremony", "public")
	d := dockerDriver{image: p.Image, platform: p.Platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony", root: root, definition: filepath.Join(root, "ceremony.json"), definitionSig: filepath.Join(root, "ceremony.sig"), coordinatorKey: hostKey, client: client.BindHost(endpoint)}
	return d.inspector(), command, nil
}

func (f *roleFlow) authenticatedDefinition() (transcript.Definition, error) {
	if f.definition != nil {
		return f.definition()
	}
	i, bindings, err := f.inspectionContext()
	if err != nil {
		return transcript.Definition{}, err
	}
	d, err := i.Definition()
	if err != nil {
		return transcript.Definition{}, err
	}
	if err := f.bindPublicInputs(bindings); err != nil {
		return transcript.Definition{}, err
	}
	return d, nil
}

func (f *roleFlow) authenticatedJourney() (transcript.Journey, error) {
	i, bindings, err := f.inspectionContext()
	if err != nil {
		return transcript.Journey{}, err
	}
	j, err := i.Journey()
	if err != nil {
		return transcript.Journey{}, err
	}
	if err := f.bindPublicInputs(bindings); err != nil {
		return transcript.Journey{}, err
	}
	return j, nil
}

func (f *roleFlow) decisionRequirement() (string, error) {
	d, err := f.authenticatedDefinition()
	if err != nil {
		return "", fmt.Errorf("cannot determine production decision requirements until the signed definition is authenticated: %w", err)
	}
	switch d.Mode {
	case "rehearsal":
		return "not-applicable", nil
	case "production":
		return "required", nil
	default:
		return "", errors.New("unknown authenticated ceremony mode; do not omit the production gate")
	}
}

// resolvePolicyTask derives guidance and CLI defaults only from the
// authenticated definition. It never makes an optional control mandatory and
// never weakens proof-tool verification.
func (f *roleFlow) resolvePolicyTask(task flowTask) (flowTask, bool, error) {
	needsPolicy := task.Assurance != "" || task.ID == "close" || task.ID == "ops-prepare" ||
		(f.state.Role == "release-signer" && task.ID == "sign") ||
		(f.state.Role == "coordinator" && task.ID == "verify-decision")
	if !needsPolicy {
		return task, true, nil
	}
	d, err := f.authenticatedDefinition()
	if err != nil {
		return task, false, err
	}
	requirements, err := d.RequireJourney()
	if err != nil {
		return task, false, err
	}
	count := map[string]int{
		"witness": requirements.MinimumPublicWitnesses,
		"mirror":  requirements.MinimumMirrorsPerAcceptedHead,
		"audit":   requirements.MinimumPassingCeremonyAudits,
	}[task.Assurance]
	if task.Assurance != "" && count == 0 {
		return task, false, nil
	}
	for index := range task.Fields {
		field := &task.Fields[index]
		if task.ID == "close" && field.Flag == "beacon-round-lead" && requirements.BeaconRoundLeadSeconds > 0 {
			field.Default = fmt.Sprint(requirements.BeaconRoundLeadSeconds)
			field.Label = "Signed seconds from closure to the future beacon round"
		}
	}
	// Modern proof-tool derives the exact witness quorum from the signed
	// definition. An operator-controlled flag would be ambiguous and is rejected.
	if task.ID == "ops-prepare" {
		fields := make([]flowField, 0, len(task.Fields))
		for _, field := range task.Fields {
			if field.Flag != "witness-quorum" {
				fields = append(fields, field)
			}
		}
		task.Fields = fields
	}
	if (f.state.Role == "release-signer" && task.ID == "sign") ||
		(f.state.Role == "coordinator" && task.ID == "verify-decision") {
		if requirements.MinimumPassingCeremonyAudits == 0 {
			fields := make([]flowField, 0, len(task.Fields))
			for _, field := range task.Fields {
				if field.Flag != "audit-report" && field.Flag != "audit-signature" &&
					!(task.ID == "verify-decision" && field.Flag == "signature" && strings.Contains(strings.ToLower(field.Label), "auditor")) {
					fields = append(fields, field)
				}
			}
			task.Fields, task.ExtraFields, task.ExtraLabel = fields, nil, ""
		}
	}
	return task, true, nil
}

func (f *roleFlow) requireEnabledRole() error {
	gate := map[string]string{"witness": "witness", "mirror": "mirror", "auditor": "audit"}[f.state.Role]
	if gate == "" {
		return nil
	}
	_, enabled, err := f.resolvePolicyTask(flowTask{Assurance: gate})
	if err != nil {
		return fmt.Errorf("authenticate the signed definition before opening this role: %w", err)
	}
	if !enabled {
		return fmt.Errorf("%s role is disabled by the signed ceremony assurance policy", f.state.Role)
	}
	return nil
}

func (f *roleFlow) checkScheduledTurns() error {
	phase := strings.TrimSuffix(f.stages[f.state.Stage].ID, "-turns")
	phase = strings.TrimSuffix(phase, "-close")
	d, err := f.authenticatedDefinition()
	if err != nil {
		return err
	}
	schedule, err := d.Schedule(phase)
	if err != nil {
		return err
	}
	head, err := f.discoverHead(phase, nil)
	if err != nil {
		return err
	}
	if len(head.Chain.Records) != len(schedule) {
		return fmt.Errorf("waiting for scheduled contributions: authenticated local %s head has %d of %d; the signed minimum does not silently cancel the remaining participants", phase, len(head.Chain.Records), len(schedule))
	}
	return nil
}

func (f *roleFlow) nextTurnAction() (string, error) {
	phase := strings.TrimSuffix(f.stages[f.state.Stage].ID, "-turns")
	d, err := f.authenticatedDefinition()
	if err != nil {
		return "", err
	}
	schedule, err := d.Schedule(phase)
	if err != nil {
		return "", err
	}
	head, err := f.discoverHead(phase, nil)
	if err != nil {
		return "", err
	}
	if len(head.Chain.Records) >= len(schedule) {
		return "", nil
	}
	next := schedule[len(head.Chain.Records)]
	f.turnScope = &flowTurnScope{Phase: phase, Participant: next, Head: head.Digest}
	fmt.Fprintf(f.ui.output, "Next scheduled participant: %s (%d/%d). Acceptance must be independently verified.\n", next, len(head.Chain.Records)+1, len(schedule))
	for _, task := range f.stages[f.state.Stage].Tasks {
		if task.ID == "grant" {
			if a := f.last(task); a != nil && a.Status == "succeeded" && commandValue(a.Command, "identity") == next {
				local, err := f.publicHostPath(commandValue(a.Command, "out"))
				if err != nil {
					return "grant", nil
				}
				grant, err := loadGrant(local)
				if err != nil || grant.CheckUsable(time.Now()) != nil {
					return "grant", nil
				}
				return "accept", nil
			}
		}
	}
	return "grant", nil
}
