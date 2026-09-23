package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type workflowV4CommandResources struct {
	Schema        string              `json:"schema"`
	CommandDigest string              `json:"command_digest"`
	Limits        dockerRuntimeLimits `json:"limits"`
}

// The workspace lock held by the guide serializes allocation recording. Exact
// command and runtime identity define a retry; preferences do not. This record
// authorizes no command or artifact and is never a mathematical verification cache.
func retainedWorkflowV4CommandResources(profile guidedProfile, command []string) (dockerRuntimeLimits, error) {
	limits, err := resolvedDockerRuntimeLimits(profile.Resources)
	if err != nil {
		return dockerRuntimeLimits{}, err
	}
	if !filepath.IsAbs(profile.Work) || filepath.Clean(profile.Work) != profile.Work {
		return dockerRuntimeLimits{}, errors.New("resource record requires an absolute clean workspace")
	}
	// Credentials and display/profile preferences are not proof runtime identity.
	// Rotating a storage credential must not turn an exact retry into a new job.
	raw, err := json.Marshal(struct {
		Role, Image, Platform, Work, Trust, Keys string
		Command                                  []string
	}{profile.Role, profile.Image, profile.Platform, profile.Work, profile.Trust, profile.Keys, command})
	if err != nil {
		return dockerRuntimeLimits{}, err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	dir := filepath.Join(profile.Work, "workflow-v4", "resources")
	if err := ensurePrivateDirectory(dir); err != nil {
		return dockerRuntimeLimits{}, err
	}
	path := filepath.Join(dir, digest+".json")
	var saved workflowV4CommandResources
	err = readWorkflowV4JSON(path, &saved)
	if errors.Is(err, os.ErrNotExist) {
		saved = workflowV4CommandResources{Schema: "relay-command-resources-v1", CommandDigest: digest, Limits: limits}
		if err := writeJSONNoReplace(path, saved, 0600); err != nil {
			return dockerRuntimeLimits{}, err
		}
	} else if err != nil {
		return dockerRuntimeLimits{}, err
	}
	if saved.Schema != "relay-command-resources-v1" || saved.CommandDigest != digest {
		return dockerRuntimeLimits{}, errors.New("saved command resource binding is invalid")
	}
	if err := saved.Limits.validate(); err != nil {
		return dockerRuntimeLimits{}, err
	}
	return saved.Limits, nil
}

// Each read-only verification invocation can use current resource preferences;
// it does not resume a mutating operation or confer verification-cache authority.
func workflowV4ReadOnlyProofCommand(command []string) bool {
	if len(command) < 2 || command[0] != "mpc-ceremony" {
		return false
	}
	return command[1] == "inspect" || (len(command) > 2 && command[1] == "release" && command[2] == "verify")
}
