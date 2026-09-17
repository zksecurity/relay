package main

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

// executePreparedContribution consumes the freshly synchronized turn and the
// exact saved operation. It delegates isolation/cleanup to the existing driver;
// a successful return still requires retained-output reconciliation.
func (j *workflowV4Journal) executePreparedContribution(id, dockerCLI string, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, local storagefirst.LocalTurnV4) error {
	op, err := j.pending()
	if err != nil {
		return err
	}
	if op == nil || op.Plan.ID != id || op.Plan.Kind != "contribute" || op.Status != "prepared" {
		return errors.New("prepared contribution required")
	}
	p := op.Plan
	b := j.state.Marker.Binding
	if err := validateWorkflowV4Plan(p, b); err != nil {
		return err
	}
	if local.PendingOperation {
		return errors.New("resolve the earlier operation before contribution")
	}
	r, err := snapshot.RecommendTurnV4(protocol, p.Scope.Phase, storagefirst.Participant, b.IdentityID, local, "", time.Now().UTC())
	if err != nil {
		return err
	}
	if r.Action != "contribute" || !r.Ready || r.Scope != p.Scope || r.AttemptID != p.AttemptID {
		return errors.New("authenticated turn does not authorize this saved contribution")
	}
	if !filepath.IsAbs(dockerCLI) || filepath.Clean(dockerCLI) != dockerCLI {
		return errors.New("exact local Docker CLI path required")
	}
	o, pos, when, err := workflowV4ContributionOptions(p)
	if err != nil {
		return err
	}
	d := &dockerDriver{image: p.Runtime.Image, platform: p.Runtime.Platform, ceremonyBinary: dockerCeremonyBinary, root: o.root, definition: o.definition, definitionSig: o.definitionSig, coordinatorKey: o.coordinatorKey, signingKey: o.signingKey, environment: o.envPath, candidateRoot: filepath.Dir(o.outDir), executionIntentPath: workflowV4ContributorIntentPath(b.Work, p.ID), client: osDockerCommandClient{binary: dockerCLI}, now: time.Now}
	o.docker = d
	if err := workflowV4OutputsAbsent(p); err != nil {
		return err
	}
	if err := workflowV4InputsMatch(p); err != nil {
		return err
	}
	d.replaceUnstartedIntent = true // The durable operation is still prepared.
	d.beforeCreate = func() error {
		if err := workflowV4OutputsAbsent(p); err != nil {
			return err
		}
		if err := workflowV4InputsMatch(p); err != nil {
			return err
		}
		return j.transition(id, "running")
	}
	if err := runNextAt(o, pos, when); err != nil {
		if errors.Is(err, errContributorNotCreated) {
			if transitionErr := j.transition(id, "failed-no-effects"); transitionErr != nil {
				return errors.Join(err, transitionErr)
			}
		}
		return err
	}
	return j.transition(id, "returned-needs-verification")
}

func workflowV4ContributionOptions(p workflowV4OperationPlan) (roleOpts, position, time.Time, error) {
	var o roleOpts
	var pos position
	var zero time.Time
	if p.Kind != "contribute" || len(p.Command) < 3 || len(p.Command)%2 != 1 {
		return o, pos, zero, errors.New("invalid saved contribution command")
	}
	flags := map[string]string{}
	for n := 3; n < len(p.Command); n += 2 {
		flags[p.Command[n]] = p.Command[n+1]
	}
	paths := map[string]string{}
	for flag, value := range flags {
		if !strings.HasPrefix(value, "/") {
			continue
		}
		for destination, source := range p.Runtime.Mounts {
			if path, err := pathWithin(destination, value, source); err == nil {
				paths[flag] = path
				break
			}
		}
		if paths[flag] == "" {
			return o, pos, zero, errors.New("contribution path has no saved mount")
		}
	}
	when, err := time.Parse(time.RFC3339, flags["--contributed-at"])
	if err != nil {
		return o, pos, zero, err
	}
	o = roleOpts{root: paths["--transcript-dir"], definition: paths["--ceremony"], definitionSig: paths["--ceremony-signature"], coordinatorKey: paths["--coordinator-public-key-file"], phase: p.Scope.Phase, role: p.Scope.ParticipantID, signingKey: paths["--participant-signing-key"], envPath: paths["--environment"], outDir: paths["--out-dir"], operationID: p.ID, phase1Seal: paths["--phase1-seal"], phase1SealSig: paths["--phase1-seal-signature"], artifactRoot: paths["--artifact-root"], checkpoint: paths["--checkpoint"], checkpointSig: paths["--checkpoint-signature"], attemptID: flags["--attempt-id"]}
	pos.chainPath = paths["--chain"]
	pos.chain.ChainSignaturePath = paths["--chain-signature"]
	pos.nextID, pos.nextIndex = o.role, int(p.Scope.Index)
	// Compare the driver's logical argv to the immutable plan before rewriting
	// any mount paths or creating a Docker container.
	actual := append([]string{"mpc-ceremony"}, contributionCommandArgs(o, pos, when)...)
	for n, value := range actual {
		if !filepath.IsAbs(value) {
			continue
		}
		actual[n], err = workflowV4ContainerPath(p.Runtime, value)
		if err != nil {
			return o, pos, zero, err
		}
	}
	if !reflect.DeepEqual(actual, p.Command) {
		return o, pos, zero, errors.New("driver contribution differs from the saved command")
	}
	return o, pos, when, nil
}
