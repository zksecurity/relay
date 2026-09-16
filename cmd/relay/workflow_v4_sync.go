package main

import (
	"errors"
	"path/filepath"

	"github.com/zksecurity/relay/internal/state"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

// syncV4 is called with the role workspace lock held. The caller supplies the
// configured storage client, never a destination discovered in an artifact.
// Each verification mounts only the temporary public metadata root created by
// SyncV4; the normal inspector's fixed transcript mount cannot cover that root.
func (j *workflowV4Journal) syncV4(objects storagefirst.ObjectStore, trust transcript.Inspector, dockerCLI string) (storagefirst.SnapshotV4, error) {
	var zero storagefirst.SnapshotV4
	if objects == nil {
		return zero, errors.New("configured storage required")
	}
	if j.lock == nil || j.writeErr != nil {
		return zero, errors.New("active healthy V4 workspace required")
	}
	if !filepath.IsAbs(dockerCLI) || filepath.Clean(dockerCLI) != dockerCLI {
		return zero, errors.New("exact local Docker CLI path required")
	}
	b := j.state.Marker.Binding
	r := b.Runtimes["online"]
	if err := validateWorkflowV4Runtime(r, b.Work); err != nil {
		return zero, err
	}
	if _, err := pathWithin(r.Mounts["/trust"], trust.CoordinatorPublicKeyPath, "/trust"); err != nil {
		return zero, err
	}
	if err := workflowV4InputsMatch(workflowV4OperationPlan{Inputs: []workflowV4Input{{Path: trust.CeremonyPath, Ref: b.Definition.Record}, {Path: trust.CeremonySignaturePath, Ref: b.Definition.Signature}}}); err != nil {
		return zero, err
	}
	d := dockerDriver{image: r.Image, platform: r.Platform, definition: trust.CeremonyPath, definitionSig: trust.CeremonySignaturePath, coordinatorKey: trust.CoordinatorPublicKeyPath, client: osDockerCommandClient{binary: dockerCLI}}
	if err := d.authenticateDaemon(); err != nil {
		return zero, err
	}
	if err := prepareGuidedImage(r.Image, r.Platform, dockerCLI, false); err != nil {
		return zero, err
	}
	trust.Runner = func(executable string, args ...string) ([]byte, []byte, error) {
		if executable != "mpc-ceremony" && executable != "/usr/local/bin/mpc-ceremony" {
			return nil, nil, errors.New("unexpected V4 metadata executable")
		}
		if len(args) < 4 || args[0] != "--format" || args[1] != "json" || args[2] != "checkpoint" || (args[3] != "inspect-signed-v4" && args[3] != "inspect-enrollments-v4") {
			return nil, nil, errors.New("metadata synchronization cannot execute another command")
		}
		root := commandValue(args, "artifact-root")
		if _, err := pathWithin(b.Work, root, "/work"); err != nil {
			return nil, nil, err
		}
		if err := validateCommitLocalPath(root); err != nil {
			return nil, nil, err
		}
		child := d
		child.root = root
		rewritten, mounts, err := child.rewriteReadOnlyArgs(args)
		if err != nil {
			return nil, nil, err
		}
		command := append(child.baseRunArgs(true, mounts), child.image)
		return child.client.Output(append(command, rewritten...)...)
	}
	trust.Executable = "mpc-ceremony"
	highWater, err := state.OpenWorkspaceHighWater(b.Work, b.CeremonyID)
	if err != nil {
		return zero, err
	}
	return storagefirst.SyncV4(objects, trust, highWater, b.CeremonyID, b.Work)
}
