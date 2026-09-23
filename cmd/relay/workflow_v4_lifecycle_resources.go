package main

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/zksecurity/relay/internal/transcript"
)

type workflowV4ResourceOrigin struct {
	Schema string                        `json:"schema"`
	Head   transcript.SignedArtifactRefs `json:"head"`
	Legacy bool                          `json:"legacy"`
}

func validateWorkflowV4ResourceOrigin(origin workflowV4ResourceOrigin) error {
	if origin.Schema != "relay-workflow-v4-resource-origin-v1" {
		return errors.New("unknown resource migration origin")
	}
	if err := validateWorkflowV4Ref(origin.Head.Record); err != nil {
		return err
	}
	return validateWorkflowV4Ref(origin.Head.Signature)
}

// Call under the workspace lock after authenticating the first synchronized head.
// The first head of an older workspace is an ambiguous recovery boundary, not
// evidence that a missing output represents a new computation.
func ensureWorkflowV4ResourceOrigin(work string, head transcript.SignedArtifactRefs, fresh bool) (workflowV4ResourceOrigin, error) {
	path := filepath.Join(work, "workflow-v4", "coordinator", "resource-origin.json")
	var origin workflowV4ResourceOrigin
	err := readWorkflowV4JSON(path, &origin)
	if errors.Is(err, os.ErrNotExist) {
		origin = workflowV4ResourceOrigin{Schema: "relay-workflow-v4-resource-origin-v1", Head: head, Legacy: !fresh}
		if err := validateWorkflowV4ResourceOrigin(origin); err != nil {
			return origin, err
		}
		if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
			return origin, err
		}
		if err := writeJSONNoReplace(path, origin, 0600); err != nil {
			return origin, err
		}
	} else if err != nil {
		return origin, err
	}
	return origin, validateWorkflowV4ResourceOrigin(origin)
}

func workflowV4LifecycleNewLimits(profile guidedProfile, head transcript.SignedArtifactRefs) (dockerRuntimeLimits, error) {
	origin, err := ensureWorkflowV4ResourceOrigin(profile.Work, head, false)
	if err != nil {
		return dockerRuntimeLimits{}, err
	}
	if origin.Legacy && origin.Head == head {
		return resolvedDockerRuntimeLimits(nil)
	}
	return resolvedDockerRuntimeLimits(profile.Resources)
}
