package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
)

func workflowV4ContributorIntentPath(work, id string) string {
	return filepath.Join(work, "workflow-v4", "contributor-"+id+".json")
}

func (j *workflowV4Journal) validateCleanupContribution(p workflowV4OperationPlan, r dockerLifecycleReceipt, candidate string) error {
	var prior *workflowV4Operation
	for n := range j.state.Operations {
		op := &j.state.Operations[n]
		if op.Plan.Kind == "contribute" && op.Plan.Scope == p.Scope && op.Status == "reconciled" && op.Plan.ID == r.OperationID {
			prior = op
			break
		}
	}
	if prior == nil || prior.Plan.Predecessor != p.Predecessor || len(prior.Plan.Outputs) != 1 || prior.Plan.Outputs[0] != candidate || prior.Plan.Runtime.Image != r.Image || prior.Plan.Runtime.Platform != r.Platform {
		return errors.New("cleanup lifecycle does not match the reconciled contribution operation")
	}
	return j.validateContributionLifecycle(prior.Plan, r, candidate)
}

func (j *workflowV4Journal) validateContributionLifecycle(p workflowV4OperationPlan, r dockerLifecycleReceipt, candidate string) error {
	if p.Kind != "contribute" || p.ID != r.OperationID || len(p.Outputs) != 1 || p.Outputs[0] != candidate || p.Runtime.Image != r.Image || p.Runtime.Platform != r.Platform {
		return errors.New("lifecycle does not match contribution plan")
	}
	var intent dockerActiveState
	if err := readWorkflowV4JSON(workflowV4ContributorIntentPath(j.state.Marker.Binding.Work, p.ID), &intent); err != nil {
		return err
	}
	if !validDockerActiveState(intent) || intent.OperationID != p.ID || intent.WorkspaceID != r.WorkspaceID || intent.Image != r.Image || intent.Platform != r.Platform || intent.DaemonID != r.Daemon.ID || intent.DaemonEndpoint != r.Daemon.Endpoint || len(intent.CreateArgs) == 0 {
		return errors.New("cleanup lifecycle differs from the original Docker invocation")
	}
	limits, err := resolvedDockerRuntimeLimits(p.Runtime.Resources)
	if err != nil {
		return err
	}
	recorded, err := resolvedDockerRuntimeLimits(intent.RuntimeLimits)
	if err != nil {
		return err
	}
	if limits != recorded || (r.Schema == dockerLifecycleSchema && !limits.matchesSecurityFacts(r.Security)) {
		return errors.New("cleanup lifecycle resource allocation differs from the saved contribution")
	}
	destination := sha256.Sum256([]byte(filepath.Clean(candidate)))
	invocation, _ := json.Marshal(intent.CreateArgs)
	digest := sha256.Sum256(invocation)
	if r.CandidateDirectorySHA256 != fmt.Sprintf("sha256:%x", destination) || r.CreateArgsSHA256 != fmt.Sprintf("sha256:%x", digest) {
		return errors.New("cleanup lifecycle has another candidate or Docker command")
	}
	return nil
}
