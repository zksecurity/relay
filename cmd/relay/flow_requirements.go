package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

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

func (f *roleFlow) checkScheduledTurns() error {
	phase := strings.TrimSuffix(f.stages[f.state.Stage].ID, "-turns")
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
