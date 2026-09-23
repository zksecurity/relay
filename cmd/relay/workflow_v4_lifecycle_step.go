package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/zksecurity/relay/internal/transcript"
)

// A retained timestamp belongs to a logical step, not to a reconstructed argv.
// This is private execution state and conveys no transcript verification authority.
type workflowV4LifecycleStep struct {
	Schema      string                        `json:"schema"`
	Predecessor transcript.SignedArtifactRefs `json:"predecessor"`
	Step        string                        `json:"step"`
	Output      string                        `json:"output"`
	Image       string                        `json:"image"`
	Platform    string                        `json:"platform"`
	At          string                        `json:"at"`
	Resources   *dockerRuntimeLimits          `json:"resources,omitempty"`
	Command     []string                      `json:"command,omitempty"`
	Trust       string                        `json:"trust,omitempty"`
	Keys        string                        `json:"keys,omitempty"`
}

const workflowV4LifecycleStepSchema = "relay-workflow-v4-lifecycle-step-v2"
const workflowV4LegacyLifecycleStepSchema = "relay-workflow-v4-lifecycle-step-v1"

func lifecycleStepDigest(head transcript.SignedArtifactRefs, step string) string {
	raw, _ := json.Marshal(struct {
		Head transcript.SignedArtifactRefs
		Step string
	}{head, step})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func validateWorkflowV4LifecycleStep(s workflowV4LifecycleStep, work string) error {
	if (s.Schema != workflowV4LifecycleStepSchema && s.Schema != workflowV4LegacyLifecycleStepSchema) || s.Image == "" || s.Platform == "" {
		return errors.New("invalid retained lifecycle step")
	}
	switch s.Step {
	case "finalize-preliminary", "finalize-complete", "prepare-evidence-bundle", "sign-evidence-bundle", "record-release-review", "rehearsal-evidence", "record-final-candidate", "seal-phase1", "record-phase1-seal", "derive-phase2", "record-phase2-genesis", "close-phase1", "close-phase2", "record-phase1-closure", "record-phase2-closure", "beacon-phase1", "beacon-phase2", "record-phase1-beacon", "record-phase2-beacon", "record-final-release", "release-review", "sign-release":
	default:
		return errors.New("unknown retained lifecycle step")
	}
	if err := validateWorkflowV4Ref(s.Predecessor.Record); err != nil {
		return err
	}
	if err := validateWorkflowV4Ref(s.Predecessor.Signature); err != nil {
		return err
	}
	if _, err := pathWithin(work, s.Output, "/work"); err != nil {
		return err
	}
	if _, err := time.Parse(time.RFC3339Nano, s.At); err != nil {
		return err
	}
	if s.Schema == workflowV4LifecycleStepSchema {
		if s.Resources == nil {
			return errors.New("lifecycle step is missing retained resources")
		}
		if err := s.Resources.validate(); err != nil {
			return err
		}
	} else if s.Resources != nil || len(s.Command) != 0 {
		return errors.New("legacy lifecycle step contains unexpected execution metadata")
	}
	return nil
}

func retainedWorkflowV4LifecycleTime(profile guidedProfile, head transcript.SignedArtifactRefs, step, output string, now time.Time) (time.Time, error) {
	saved, err := retainedWorkflowV4LifecycleStep(profile, head, step, output, now)
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, saved.At)
}

func retainedWorkflowV4LifecycleStep(profile guidedProfile, head transcript.SignedArtifactRefs, step, output string, now time.Time) (workflowV4LifecycleStep, error) {
	path := filepath.Join(profile.Work, "workflow-v4", "coordinator", "lifecycle", lifecycleStepDigest(head, step)+".json")
	var saved workflowV4LifecycleStep
	err := readWorkflowV4JSON(path, &saved)
	if errors.Is(err, os.ErrNotExist) {
		limits, err := workflowV4LifecycleNewLimits(profile, head)
		if err != nil {
			return saved, err
		}
		saved = workflowV4LifecycleStep{Schema: workflowV4LifecycleStepSchema, Predecessor: head, Step: step, Output: output, Image: profile.Image, Platform: profile.Platform, Trust: profile.Trust, Keys: profile.Keys, At: now.UTC().Format(time.RFC3339Nano), Resources: &limits}
		if err := validateWorkflowV4LifecycleStep(saved, profile.Work); err != nil {
			return saved, err
		}
		if err := ensurePrivateDirectory(filepath.Dir(path)); err != nil {
			return saved, err
		}
		if err := writeJSONNoReplace(path, saved, 0600); err != nil {
			return saved, err
		}
	} else if err != nil {
		return saved, err
	}
	if err := validateWorkflowV4LifecycleStep(saved, profile.Work); err != nil {
		return saved, err
	}
	if saved.Predecessor != head || saved.Step != step || saved.Output != output || saved.Image != profile.Image || saved.Platform != profile.Platform {
		return saved, errors.New("retained lifecycle step differs from requested operation")
	}
	if saved.Schema == workflowV4LegacyLifecycleStepSchema {
		limits, _ := resolvedDockerRuntimeLimits(nil)
		saved.Schema, saved.Resources, saved.Trust, saved.Keys = workflowV4LifecycleStepSchema, &limits, profile.Trust, profile.Keys
		if err := writeJSONAtomic(path, saved, 0600); err != nil {
			return saved, err
		}
	}
	if saved.Trust != profile.Trust || saved.Keys != profile.Keys {
		return saved, errors.New("retained lifecycle mounts differ from requested operation")
	}
	return saved, nil
}

func runWorkflowV4LifecycleCommand(profile guidedProfile, head transcript.SignedArtifactRefs, step, output string, command []string) error {
	saved, err := retainedWorkflowV4LifecycleStep(profile, head, step, output, time.Now().UTC())
	if err != nil {
		return err
	}
	if len(command) < 2 || command[0] != "mpc-ceremony" {
		return errors.New("lifecycle step requires a proof-tool command")
	}
	if len(saved.Command) == 0 {
		saved.Command = append([]string(nil), command...)
		path := filepath.Join(profile.Work, "workflow-v4", "coordinator", "lifecycle", lifecycleStepDigest(head, step)+".json")
		if err := writeJSONAtomic(path, saved, 0600); err != nil {
			return err
		}
	} else if !reflect.DeepEqual(saved.Command, command) {
		return errors.New("retained lifecycle command differs from requested operation")
	}
	profile.Resources = saved.Resources
	return runWorkflowV4ProfileCommandWithRetention(profile, command, false, false)
}
