package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/transcript"
)

type workflowV4ParticipantProgress struct {
	Local        storagefirst.LocalTurnV4
	Contribution *workflowV4Operation
	Cleanup      *workflowV4Operation
	Upload       *workflowV4Operation
}

func (j *workflowV4Journal) participantProgressV4(scope transcript.ContributionScopeV4, dockerCLI string) (workflowV4ParticipantProgress, error) {
	var progress workflowV4ParticipantProgress
	progress.Local.Scope = scope
	for n := range j.state.Operations {
		op := &j.state.Operations[n]
		if op.Plan.Scope != scope {
			continue
		}
		switch op.Plan.Kind {
		case "contribute":
			if op.Status == "reconciled" {
				progress.Contribution = op
			}
		case "attest-erasure":
			if op.Status == "reconciled" {
				progress.Cleanup = op
			}
		case "upload-candidate":
			if op.Status == "reconciled" {
				progress.Upload = op
			}
		}
	}
	pending, err := j.pending()
	if err != nil {
		return progress, err
	}
	if pending != nil {
		progress.Local.PendingOperation = true
	}
	if progress.Contribution != nil {
		scopeFile := workflowV4ScopePath(j.state.Marker.Binding.Work, progress.Contribution.Plan.AttemptID)
		id := progress.Contribution.Plan.ID
		if progress.Cleanup != nil {
			id = progress.Cleanup.Plan.ID
		}
		facts, err := j.reconcileCandidateOperation(id, scopeFile, dockerCLI)
		if err != nil {
			return progress, fmt.Errorf("recheck retained candidate: %w", err)
		}
		progress.Local = facts
		progress.Local.PendingOperation = pending != nil
	}
	if progress.Upload != nil {
		var record workflowV4UploadRecord
		if err := readWorkflowV4JSON(progress.Upload.Plan.Outputs[0], &record); err != nil {
			return progress, err
		}
		if record.Schema != workflowV4UploadRecordSchema || record.Scope != scope || record.AttemptID != progress.Upload.Plan.AttemptID || record.CandidateResultID == "" {
			return progress, errors.New("retained upload result differs from this participant turn")
		}
		progress.Local.UploadedAttemptID = record.AttemptID
		progress.Local.UploadedArtifactID = record.CandidateResultID
	}
	return progress, nil
}

func workflowV4ScopePath(work, attempt string) string {
	return filepath.Join(work, "workflow-v4", "scopes", attempt+".json")
}

func workflowV4ParticipantActionLabel(recommendation storagefirst.TurnRecommendationV4, pending *workflowV4Operation) string {
	if pending != nil {
		switch pending.Plan.Kind {
		case "contribute":
			if pending.Status == "prepared" {
				return "Run the prepared contribution"
			}
			return "Inspect the retained contribution result"
		case "attest-erasure":
			if pending.Status == "prepared" {
				return "Create the prepared cleanup statement"
			}
			return "Inspect the retained cleanup result"
		case "upload-candidate":
			if pending.Status == "running" {
				return "Safely continue the exact candidate upload"
			}
			return "Verify the exact candidate upload"
		}
		return "Inspect the retained operation"
	}
	switch recommendation.Action {
	case "submit-your-enrollment":
		return "Upload your signed enrollment"
	case "contribute":
		return "Verify the signed allocation and contribute"
	case "confirm-cleanup-and-sign-attestation":
		return "Confirm cleanup and sign the cleanup statement"
	case "get-candidate-grant", "upload-candidate":
		return "Select your private upload grant and upload the candidate"
	}
	return ""
}

func runWorkflowV4ParticipantAction(ui *coordinatorWizard, j *workflowV4Journal, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, participant access.RoleConfig, config access.StorageConfig, inspector transcript.Inspector, dockerCLI string, view storagefirst.TurnViewV4, progress workflowV4ParticipantProgress, resources *dockerRuntimeLimits) error {
	pending, err := j.pending()
	if err != nil {
		return err
	}
	if pending != nil {
		if pending.Plan.Scope.Phase != participant.Phase || pending.Plan.Scope != view.Scope {
			return errors.New("retained operation belongs to another participant turn; resolve it before continuing")
		}
		switch pending.Plan.Kind {
		case "contribute":
			if pending.Status == "prepared" {
				if err := ui.confirm("Run the exact prepared contribution in the isolated container", "CONTRIBUTE"); err != nil {
					return err
				}
				if err := j.executePreparedContribution(pending.Plan.ID, dockerCLI, snapshot, protocol, progress.Local); err != nil {
					return err
				}
			}
			_, err := j.reconcileCandidateOperation(pending.Plan.ID, workflowV4ScopePath(j.state.Marker.Binding.Work, pending.Plan.AttemptID), dockerCLI)
			return err
		case "attest-erasure":
			if pending.Status == "prepared" {
				if err := ui.confirm("Sign the exact prepared cleanup statement", "SIGN CLEANUP"); err != nil {
					return err
				}
				if err := j.executePreparedErasure(pending.Plan.ID, workflowV4ScopePath(j.state.Marker.Binding.Work, pending.Plan.AttemptID), dockerCLI); err != nil {
					return err
				}
			}
			_, err := j.reconcileCandidateOperation(pending.Plan.ID, workflowV4ScopePath(j.state.Marker.Binding.Work, pending.Plan.AttemptID), dockerCLI)
			return err
		case "upload-candidate":
			return runWorkflowV4ParticipantUpload(ui, j, snapshot, protocol, config, dockerCLI, view, progress, pending)
		default:
			return errors.New("retained operation needs a role-specific verifier before Relay can continue")
		}
	}
	recommendation, err := snapshot.RecommendTurnV4(protocol, participant.Phase, storagefirst.Participant, participant.IdentityID, progress.Local, "", time.Now().UTC())
	if err != nil {
		return err
	}
	switch recommendation.Action {
	case "submit-your-enrollment":
		return runWorkflowV4ParticipantEnrollment(ui, snapshot, protocol, participant, config, inspector)
	case "contribute":
		if err := ui.confirm("Authenticate this assigned input, create your contribution and check it", "CONTRIBUTE"); err != nil {
			return err
		}
		plan, scopeFile, err := prepareWorkflowV4Contribution(snapshot, protocol, j.state.Marker.Binding, participant, time.Now().UTC())
		if err != nil {
			return err
		}
		limits, err := resolvedDockerRuntimeLimits(resources)
		if err != nil {
			return err
		}
		plan.Runtime.Resources = &limits
		if err := j.prepare(plan); err != nil {
			return err
		}
		if err := j.executePreparedContribution(plan.ID, dockerCLI, snapshot, protocol, storagefirst.LocalTurnV4{Scope: plan.Scope}); err != nil {
			return err
		}
		_, err = j.reconcileCandidateOperation(plan.ID, scopeFile, dockerCLI)
		return err
	case "confirm-cleanup-and-sign-attestation":
		if progress.Contribution == nil || progress.Local.GeneratedOutput == nil {
			return errors.New("verified retained computation required before cleanup")
		}
		candidate := progress.Contribution.Plan.Outputs[0]
		driver := &dockerDriver{runtimeLimits: progress.Contribution.Plan.Runtime.Resources, image: progress.Contribution.Plan.Runtime.Image, platform: progress.Contribution.Plan.Runtime.Platform}
		role := roleOpts{outDir: candidate, docker: driver}
		if err := confirmDockerNoCopiesWithIO(role, ui.input, ui.output); err != nil {
			return err
		}
		destroyedAt := erasureTimestamp(candidate, time.Now().UTC())
		if err := persistDockerErasureIntent(role, destroyedAt); err != nil {
			return err
		}
		plan, err := j.prepareWorkflowV4Erasure(progress.Contribution.Plan.ID, workflowV4ScopePath(j.state.Marker.Binding.Work, progress.Contribution.Plan.AttemptID), *progress.Local.GeneratedOutput, destroyedAt)
		if err != nil {
			return err
		}
		if err := j.prepare(plan); err != nil {
			return err
		}
		if err := j.executePreparedErasure(plan.ID, workflowV4ScopePath(j.state.Marker.Binding.Work, progress.Contribution.Plan.AttemptID), dockerCLI); err != nil {
			return err
		}
		_, err = j.reconcileCandidateOperation(plan.ID, workflowV4ScopePath(j.state.Marker.Binding.Work, progress.Contribution.Plan.AttemptID), dockerCLI)
		return err
	case "get-candidate-grant", "upload-candidate":
		return runWorkflowV4ParticipantUpload(ui, j, snapshot, protocol, config, dockerCLI, view, progress, nil)
	default:
		return fmt.Errorf("current signed state does not authorize a participant action: %s", recommendation.Reason)
	}
}

func runWorkflowV4ParticipantUpload(ui *coordinatorWizard, j *workflowV4Journal, snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, config access.StorageConfig, dockerCLI string, view storagefirst.TurnViewV4, progress workflowV4ParticipantProgress, pending *workflowV4Operation) error {
	_ = dockerCLI // retained for the common action signature; upload does not invoke Docker.
	if progress.Cleanup == nil || progress.Local.CandidateInventory == nil || view.CandidateAttempt == nil {
		return errors.New("verified five-file candidate and active upload attempt required")
	}
	path, err := ui.required("Absolute path to the private candidate upload grant received from the coordinator or Tessera", "")
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("private grant path must be absolute and clean")
	}
	grant, err := loadStorageFirstGrant(path)
	if err != nil {
		return err
	}
	destination := storagefirst.GrantDestination{Provider: config.Provider, Endpoint: config.Endpoint, Region: config.Region, InboxBucket: config.InboxBucket}
	if err := storagefirst.ValidateGrantV4At(snapshot, protocol, j.state.Marker.Binding.IdentityID, grant, destination, time.Now().UTC()); err != nil {
		return err
	}
	if pending == nil {
		plan, err := j.prepareWorkflowV4Upload(progress.Cleanup.Plan.ID, view.CandidateAttempt.AttemptID, *progress.Local.CandidateInventory)
		if err != nil {
			return err
		}
		if err := ui.confirm("Upload only the verified five public candidate files; the manifest will be last", "UPLOAD CANDIDATE"); err != nil {
			return err
		}
		if err := j.prepare(plan); err != nil {
			return err
		}
		pending, err = j.pending()
		if err != nil {
			return err
		}
	}
	if pending.Plan.AttemptID != view.CandidateAttempt.AttemptID {
		return errors.New("retained upload belongs to a retired attempt; preserve it and make a fresh contribution for the replacement allocation")
	}
	switch pending.Status {
	case "prepared":
		if err := j.executePreparedCandidateUpload(pending.Plan.ID, snapshot, protocol, grant, destination, *progress.Local.CandidateInventory, time.Now().UTC()); err != nil {
			return err
		}
	case "running":
		if err := ui.confirm("Continue the exact immutable upload; existing bytes will be compared and never replaced", "CONTINUE UPLOAD"); err != nil {
			return err
		}
		if err := j.resumeCandidateUpload(pending.Plan.ID, snapshot, protocol, grant, destination, *progress.Local.CandidateInventory, time.Now().UTC()); err != nil {
			return err
		}
	case "returned-needs-verification":
	default:
		return errors.New("candidate upload is not in a resumable state")
	}
	return j.reconcileCandidateUpload(pending.Plan.ID, storageFirstGrantClient(grant), *progress.Local.CandidateInventory)
}

func workflowV4ParticipantRecommendation(snapshot storagefirst.SnapshotV4, protocol transcript.DefinitionProtocol, participant access.RoleConfig, progress workflowV4ParticipantProgress, now time.Time) (storagefirst.TurnRecommendationV4, error) {
	return snapshot.RecommendTurnV4(protocol, participant.Phase, storagefirst.Participant, participant.IdentityID, progress.Local, "", now)
}
