package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/storagefirst"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

// A hint selects the verifier, never authenticates the definition. An existing
// V4 workspace cannot fall back to legacy progress after losing its definition.
func workflowV4RouteHint(p guidedProfile) (bool, error) {
	if p.Work == "" {
		return false, nil
	}
	for _, path := range []string{filepath.Join(p.Work, ".relay-workspace-v4.json"), filepath.Join(p.Work, "workflow-v4", "state.json")} {
		if _, err := os.Lstat(path); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	raw, err := readTesseraRegularFile(filepath.Join(p.Work, "ceremony", "public", "ceremony.json"), 16<<20, false)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := rejectCommitJournalDuplicateFields(raw); err != nil {
		return false, err
	}
	var hint struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(raw, &hint); err != nil {
		return false, err
	}
	switch hint.Schema {
	case "proof-tool-mpc-ceremony-definition-v4":
		return true, nil
	case "proof-tool-mpc-ceremony-definition-v1", "proof-tool-mpc-ceremony-definition-v2", "proof-tool-mpc-ceremony-definition-v3":
		return false, nil
	default:
		return false, errors.New("unsupported ceremony format; preserve this workspace and use its matching release")
	}
}

func runWorkflowV4Guide(p guidedProfile, settingsRoot string) error {
	if p.Role != "coordinator" && p.Role != "participant" && p.Role != "release-signer" {
		return errors.New("this V4 role journey is not connected yet; no legacy actions were opened")
	}
	var participant *access.RoleConfig
	storagePath := filepath.Join(p.Work, "ceremony", "config", "relay-storage.json")
	key := filepath.Join(p.Trust, "setup-coordinator.hex")
	if p.Role == "release-signer" {
		key = filepath.Join(p.Trust, "coordinator-public-key.hex")
	}
	dockerCLI := "docker"
	if p.Role == "participant" {
		c, err := loadRoleConfig(p.Config, "participant")
		if err != nil {
			return err
		}
		participant, storagePath, key, dockerCLI = &c, c.StorageConfig, c.CoordinatorKey, c.DockerCLI
	}
	cli, err := exec.LookPath(dockerCLI)
	if err != nil {
		return err
	}
	cli, err = filepath.Abs(cli)
	if err != nil {
		return err
	}
	signerDir, err := guidedDirectory(settingsRoot, offlineRoleAlias(p.Name, p.Role), "decision-signer")
	if err != nil {
		return err
	}
	signer, err := readGuidedProfile(filepath.Join(signerDir, "profile.json"), offlineRoleAlias(p.Name, p.Role), "decision-signer")
	if err != nil {
		return fmt.Errorf("prepare this role's network-disabled signing image in onboarding: %w", err)
	}
	var identity setupIdentity
	if err := setupReadJSON(filepath.Join(p.Keys, "identity.json"), &identity); err != nil {
		return err
	}
	root := filepath.Join(p.Work, "ceremony", "public")
	// Validate runtime and confined mounts before invoking any container.
	runtime := workflowV4Runtime{Image: p.Image, Platform: p.Platform, Mounts: map[string]string{"/work": p.Work, "/trust": p.Trust, "/keys": p.Keys}}
	if err := validateWorkflowV4Runtime(runtime, p.Work); err != nil {
		return err
	}
	if _, err := pathWithin(p.Trust, key, "/trust"); err != nil {
		return err
	}
	if err := prepareGuidedImage(p.Image, p.Platform, cli, false); err != nil {
		return err
	}
	d := dockerDriver{image: p.Image, platform: p.Platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony", root: root, definition: filepath.Join(root, "ceremony.json"), definitionSig: filepath.Join(root, "ceremony.sig"), coordinatorKey: key, client: osDockerCommandClient{binary: cli}}
	if err := d.authenticateDaemon(); err != nil {
		return err
	}
	inspector := d.inspector()
	protocol, err := inspector.DefinitionProtocol()
	if err != nil {
		return fmt.Errorf("authenticate V4 ceremony; legacy fallback is disabled: %w", err)
	}
	binding, err := workflowV4ProfileBinding(p, signer, protocol, identity, participant)
	if err != nil {
		return err
	}
	j, err := openWorkflowV4Journal(protocol, protocol.DefinitionRefs, binding)
	if err != nil {
		return err
	}
	defer j.close()
	if _, err := pathWithin(p.Work, storagePath, "/work"); err != nil {
		return err
	}
	raw, err := readTesseraRegularFile(storagePath, 1<<20, false)
	if err != nil {
		return fmt.Errorf("import your coordinator's public storage settings: %w", err)
	}
	config, err := access.Decode(raw, access.StorageConfig.Validate)
	if err != nil {
		return err
	}
	if config.CeremonyID != binding.CeremonyID {
		return errors.New("storage settings belong to another ceremony")
	}
	if participant != nil && (config.PublishedBaseURL != participant.PublishedBaseURL || config.PublishedBucket != participant.PublishedBucket) {
		return errors.New("public storage settings differ from your saved participant profile")
	}
	if err := validateStorageFirstOrigin("public storage address", config.PublishedBaseURL); err != nil {
		return err
	}
	objects := store.Client{PublicBaseURL: config.PublishedBaseURL}
	ui := coordinatorWizard{input: bufio.NewReader(os.Stdin), output: os.Stdout}
	for {
		var snapshot storagefirst.SnapshotV4
		var turn storagefirst.TurnViewV4
		var progress workflowV4ParticipantProgress
		var coordinatorProgress workflowV4CoordinatorProgress
		var releaseProgress workflowV4ReleaseSignerProgress
		var recommendation storagefirst.TurnRecommendationV4
		lifecycleAction := ""
		actionLabel := ""
		pending, err := j.pending()
		if err != nil {
			return err
		}
		snapshot, err = j.syncV4(objects, inspector, cli)
		if err != nil {
			ui.message(toneError, "Storage synchronization failed: %v\nNo new ceremony action is authorized. Retained work is unchanged.\n", err)
			printWorkflowV4Pending(ui.output, pending)
		} else {
			c, err := snapshot.State()
			if err != nil {
				return err
			}
			if c.Definition != binding.Definition {
				return errors.New("backend definition differs from this role's authenticated definition")
			}
			phase, who := "phase1", ""
			if c.Progress.Phase2 != nil {
				phase = "phase2"
			}
			if p.Role == "participant" {
				who = identity.ID
				phase = participant.Phase
			}
			scheduled := false
			if p.Role != "release-signer" {
				scheduled, err = workflowV4ScheduledInPhase(protocol, phase, who)
				if err != nil {
					return err
				}
			}
			turn = storagefirst.TurnViewV4{Stage: "not-scheduled-in-this-phase"}
			if p.Role == "release-signer" {
				turn.Stage = "waiting-for-coordinator-review"
				if c.Progress.FinalRelease != nil {
					turn.Stage = "release-recorded"
				} else if c.Progress.ReleaseReview != nil {
					turn.Stage = "release-review-ready"
					releaseProgress, err = workflowV4ReleaseSignerProgressFor(p.Work)
					if err != nil {
						ui.message(toneError, "Retained release-signer work could not be verified: %v\nNo operation was repeated.\n", err)
					} else if releaseProgress.PackageReady {
						actionLabel = "Upload the exact signed release package using the private release grant"
					} else {
						actionLabel = "Review and sign the exact coordinator-reviewed release package"
					}
				}
			} else if scheduled || c.Progress.Terminal != nil {
				// For an unscheduled participant, terminal status is global;
				// never present another participant's active turn as theirs.
				if !scheduled {
					who = ""
				}
				turn, err = snapshot.TurnV4(protocol, phase, who)
				if err != nil {
					return err
				}
			}
			if p.Role == "participant" && turn.Scope.ParticipantID != "" {
				progress, err = j.participantProgressV4(turn.Scope, cli)
				if err != nil {
					ui.message(toneError, "Retained participant work could not be verified: %v\nNo operation was repeated.\n", err)
				} else {
					recommendation, err = workflowV4ParticipantRecommendation(snapshot, protocol, *participant, progress, time.Now().UTC())
					if err != nil {
						return err
					}
					actionLabel = workflowV4ParticipantActionLabel(recommendation, pending)
				}
			} else if p.Role == "coordinator" && turn.Scope.ParticipantID != "" {
				coordinatorProgress, err = workflowV4CoordinatorProgressFor(snapshot, protocol, turn, binding, config, inspector, time.Now().UTC())
				if err != nil {
					ui.message(toneError, "Retained coordinator work could not be verified: %v\nNo operation was repeated.\n", err)
				} else {
					observed := ""
					if coordinatorProgress.Local.CandidateReceivedAttemptID != "" {
						observed = coordinatorProgress.Local.CandidateReceivedAttemptID
					}
					recommendation, err = snapshot.RecommendTurnV4(protocol, phase, storagefirst.Coordinator, "", coordinatorProgress.Local, observed, time.Now().UTC())
					if err != nil {
						return err
					}
					actionLabel = workflowV4CoordinatorActionLabel(recommendation, coordinatorProgress)
				}
			} else if p.Role == "coordinator" {
				commitments, commitmentErr := snapshot.Commitments()
				if commitmentErr != nil {
					return commitmentErr
				}
				lifecycleAction, actionLabel, err = workflowV4CoordinatorLifecycleAction(c, commitments, protocol)
				if err != nil {
					return err
				}
			}
			printWorkflowV4Status(ui.output, p.Role, c, turn, pending, time.Now().UTC())
			if recommendation.Reason != "" {
				fmt.Fprintf(ui.output, "Next: %s\n", recommendation.Reason)
			}
			if actionLabel != "" {
				fmt.Fprintf(ui.output, "1) %s\n", actionLabel)
			}
		}
		fmt.Fprintln(ui.output, "[R] Refresh from storage\n[Q] Save and exit")
		answer, err := ui.ask("Choose", "Q")
		if err != nil {
			return err
		}
		switch strings.ToUpper(strings.TrimSpace(answer)) {
		case "1":
			if actionLabel == "" {
				fmt.Fprintln(ui.output, "No role action is available for the authenticated state.")
				continue
			}
			if p.Role == "participant" && participant != nil {
				if err := runWorkflowV4ParticipantAction(&ui, j, snapshot, protocol, *participant, config, inspector, cli, turn, progress); err != nil {
					ui.message(toneError, "Participant action stopped: %v\nSaved state and verified public files were retained. No action is automatically repeated.\n", err)
					continue
				}
			} else if p.Role == "coordinator" {
				var actionErr error
				if lifecycleAction != "" {
					actionErr = runWorkflowV4CoordinatorLifecycle(&ui, lifecycleAction, snapshot, protocol, p, signer, inspector)
				} else {
					actionErr = runWorkflowV4CoordinatorAction(&ui, snapshot, protocol, config, p, signer, inspector, recommendation, turn, coordinatorProgress)
				}
				if actionErr != nil {
					ui.message(toneError, "Coordinator action stopped: %v\nSigned files and verified downloads were retained. No action is automatically repeated.\n", actionErr)
					continue
				}
			} else if p.Role == "release-signer" {
				if err := runWorkflowV4ReleaseSignerAction(&ui, snapshot, protocol, config, p, signer, identity, releaseProgress); err != nil {
					ui.message(toneError, "Release-signer action stopped: %v\nVerified downloads and any complete signed package were retained. No signing or upload is automatically repeated.\n", err)
					continue
				}
			}
			fmt.Fprintln(ui.output, "Action finished locally. Relay will refresh signed storage state before recommending anything else.")
		case "Q":
			return nil
		case "R":
		default:
			fmt.Fprintln(ui.output, "Choose a displayed action, R or Q.")
		}
	}
}

func printWorkflowV4Status(out io.Writer, role string, c transcript.CheckpointStateV4, turn storagefirst.TurnViewV4, pending *workflowV4Operation, checked time.Time) {
	fmt.Fprintf(out, "\nRELAY | %s | STORAGE-FIRST\n------------------------------------------------------------\nChecked storage at %s; signed update %d.\nPhase 1: %d accepted contributions.\n", strings.ToUpper(role), checked.Format(time.RFC3339), c.Sequence, c.Progress.Phase1.AcceptedCount)
	if c.Progress.Phase2 != nil {
		fmt.Fprintf(out, "Phase 2: %d accepted contributions.\n", c.Progress.Phase2.AcceptedCount)
	}
	fmt.Fprintf(out, "Backend turn status: %s\n", turn.Stage)
	if c.Progress.FinalRelease != nil {
		fmt.Fprintln(out, "Final release recorded; public publication is a separate check.")
	} else if c.Progress.ReleaseReview != nil {
		fmt.Fprintln(out, "Coordinator evidence is frozen for review; waiting for the release signer.")
	} else if c.Progress.FinalCandidate != nil {
		fmt.Fprintln(out, "Final files prepared for review; release is not yet recorded.")
	} else if c.Progress.Phase1Closure != nil && c.Progress.Phase2 == nil {
		fmt.Fprintln(out, "Phase 1 is closed; Phase 2 has not started.")
	}
	if turn.Scope.ParticipantID != "" {
		fmt.Fprintf(out, "%s turn %d: %s\n", turn.Scope.Phase, turn.Scope.Index, turn.Scope.ParticipantID)
	}
	printWorkflowV4Pending(out, pending)
	fmt.Fprintln(out, "This is the newest update returned by the configured storage service, not proof that no newer state exists elsewhere.")
	fmt.Fprintln(out, "Signatures and recorded progress checked; contribution mathematics were not replayed by this refresh.")
}

func printWorkflowV4Pending(out io.Writer, pending *workflowV4Operation) {
	if pending != nil {
		fmt.Fprintf(out, "Retained operation needs inspection: %s (%s). It will not be repeated automatically.\n", pending.Plan.Kind, pending.Status)
	}
}

func workflowV4ScheduledInPhase(protocol transcript.DefinitionProtocol, phase, identity string) (bool, error) {
	schedule, err := protocol.Definition.Schedule(phase)
	if err != nil {
		return false, err
	}
	if identity == "" {
		return true, nil
	}
	for _, id := range schedule {
		if id == identity {
			return true, nil
		}
	}
	return false, nil
}
