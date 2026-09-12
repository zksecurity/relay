package main

// The workflow is a local navigation aid, not another ceremony state machine.
// Only proof-tool and Relay's authenticated role commands decide what is valid.
import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

const (
	roleFlowSchemaV1      = "relay-role-flow-v1"
	roleFlowSchema        = "relay-role-flow-v2"
	flowWorkspaceSchema   = "relay-workspace-marker-v1"
	flowWorkspaceFileName = ".relay-workspace.json"
)

type flowField struct {
	Flag, Label, Default, Kind string
	Optional                   bool
	Choices                    []string
}
type flowTask struct {
	ID, Label, Help string
	Command         []string
	Fields          []flowField
	ExtraFields     []flowField
	ExtraLabel      string
	Handoff         bool
	Optional        bool
	Offline         bool
}
type flowStage struct {
	ID, Label string
	Tasks     []flowTask
}
type flowAttempt struct {
	ID, Task, Stage, Status string
	OperationSchema         string            `json:"operation_schema,omitempty"`
	RecoveryClass           flowRecoveryClass `json:"recovery_class,omitempty"`
	ImageDigest             string            `json:"image_digest,omitempty"`
	Platform                string            `json:"platform,omitempty"`
	Command                 []string
	StartedAt, FinishedAt   string
	Note                    string
	Mounts                  map[string]string `json:"mounts,omitempty"`
	ExpectedOutputs         map[string]string `json:"expected_outputs,omitempty"`
	InputBindings           map[string]string `json:",omitempty"`
	DirectoryBindings       map[string]string `json:",omitempty"`
	ReceiptScope            *flowReceiptScope `json:",omitempty"`
	TurnScope               *flowTurnScope    `json:",omitempty"`
}
type flowTurnScope struct{ Phase, Participant, Head string }
type roleFlowState struct {
	Schema, Name, Role string
	WorkspaceID        string `json:"workspace_id,omitempty"`
	WorkspaceStatus    string `json:"workspace_status,omitempty"`
	CatalogDigest      string
	Profile            guidedProfile
	Stage              int
	StageID            string `json:"stage_id,omitempty"`
	// ViewHistory records local screen navigation only. It never marks a
	// ceremony action complete and is deliberately separate from Attempts.
	ViewHistory    []int `json:"view_history,omitempty"`
	Values         map[string]string
	Attempts       []flowAttempt
	PublicBindings map[string]string
}

type flowWorkspaceMarker struct {
	Schema      string `json:"schema"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	Role        string `json:"role"`
}
type roleFlow struct {
	state        roleFlowState
	stages       []flowStage
	path         string
	settingsRoot string
	ui           coordinatorWizard
	run          func(flowTask, []string, string, bool) error
	definition   func() (transcript.Definition, error)
	turnScope    *flowTurnScope
}

func (f *roleFlow) save() error {
	if f.state.Stage == len(f.stages) {
		f.state.StageID = "complete"
	} else if f.state.Stage >= 0 && f.state.Stage < len(f.stages) {
		f.state.StageID = f.stages[f.state.Stage].ID
	}
	return saveJSONAtomic(f.path, f.state)
}

func migrateFlowCatalog(statePath, digest string, stages []flowStage, state *roleFlowState) error {
	if state.CatalogDigest == digest {
		if state.StageID == "" {
			if state.Stage == len(stages) {
				state.StageID = "complete"
			} else if state.Stage >= 0 && state.Stage < len(stages) {
				state.StageID = stages[state.Stage].ID
			}
			if state.Schema == roleFlowSchema {
				return saveJSONAtomic(statePath, state)
			}
		}
		return nil
	}
	if state.Schema != roleFlowSchema || state.StageID == "" {
		return errors.New("workflow uses an older menu catalog without a stable stage ID; preserve it for compatibility review")
	}
	stage := -1
	if state.StageID == "complete" {
		stage = len(stages)
	} else {
		for index := range stages {
			if stages[index].ID == state.StageID {
				stage = index
				break
			}
		}
	}
	if stage < 0 {
		return fmt.Errorf("saved workflow stage %q is not present in this release", state.StageID)
	}
	old := strings.TrimPrefix(state.CatalogDigest, "sha256:")
	if len(old) < 12 {
		return errors.New("saved workflow catalog digest is invalid")
	}
	if err := backupPrivateFile(statePath, ".pre-catalog-"+old[:12]+".bak"); err != nil {
		return fmt.Errorf("preserve workflow before catalog migration: %w", err)
	}
	state.Stage, state.CatalogDigest, state.ViewHistory = stage, digest, nil
	if err := saveJSONAtomic(statePath, state); err != nil {
		return err
	}
	return nil
}

func flowWorkspaceMarkerPath(p guidedProfile) (string, error) {
	if p.Work == "" || !filepath.IsAbs(p.Work) || filepath.Clean(p.Work) != p.Work {
		return "", errors.New("guided recovery requires an absolute role work directory")
	}
	return filepath.Join(p.Work, flowWorkspaceFileName), nil
}

// ensureFlowWorkspace makes loss of the host-only recovery document visible.
// The state file is written first as initializing, then the create-only marker
// is installed in the role work directory, and only then is the state ready.
// Re-entering while initializing can finish that same sequence safely.
func ensureFlowWorkspace(statePath string, p guidedProfile, state *roleFlowState, existed bool) error {
	markerPath, err := flowWorkspaceMarkerPath(p)
	if err != nil {
		return err
	}
	var marker flowWorkspaceMarker
	markerErr := setupReadJSON(markerPath, &marker)
	markerExists := markerErr == nil
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return fmt.Errorf("read recovery workspace marker: %w", markerErr)
	}
	if !existed {
		if markerExists {
			return errors.New("recovery state is missing for an existing role workspace; preserve the folder and do not start another operation")
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		state.Schema, state.WorkspaceID, state.WorkspaceStatus = roleFlowSchema, id, "initializing"
		if err := saveJSONAtomic(statePath, state); err != nil {
			return err
		}
	}
	if state.Schema == roleFlowSchemaV1 {
		if markerExists {
			return errors.New("an old workflow has an unexpected recovery marker; preserve both files for review")
		}
		if err := backupPrivateFile(statePath, ".pre-recovery-v2.bak"); err != nil {
			return fmt.Errorf("preserve old workflow before recovery migration: %w", err)
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		state.Schema, state.WorkspaceID, state.WorkspaceStatus = roleFlowSchema, id, "initializing"
		if err := saveJSONAtomic(statePath, state); err != nil {
			return err
		}
	}
	if state.Schema != roleFlowSchema || state.WorkspaceID == "" || (state.WorkspaceStatus != "initializing" && state.WorkspaceStatus != "ready") {
		return errors.New("recovery workspace state is invalid")
	}
	want := flowWorkspaceMarker{Schema: flowWorkspaceSchema, WorkspaceID: state.WorkspaceID, Name: state.Name, Role: state.Role}
	if markerExists {
		if marker != want {
			return errors.New("recovery workspace marker does not match saved state; preserve both files and stop")
		}
	} else {
		if state.WorkspaceStatus == "ready" {
			return errors.New("recovery workspace marker is missing; do not treat this as a new role workspace")
		}
		if err := writeJSONNoReplace(markerPath, want, 0o600); err != nil {
			return fmt.Errorf("create recovery workspace marker: %w", err)
		}
	}
	if state.WorkspaceStatus == "initializing" {
		state.WorkspaceStatus = "ready"
		if err := saveJSONAtomic(statePath, state); err != nil {
			return err
		}
	}
	return nil
}

func flowNeedsOfflineSigner(stages []flowStage) bool {
	for _, stage := range stages {
		for _, task := range stage.Tasks {
			if task.Offline {
				return true
			}
		}
	}
	return false
}

func normalizeSavedParticipantProfile(saved *guidedProfile, current guidedProfile) bool {
	if saved.Role != "participant" || current.Role != "participant" {
		return false
	}
	candidate := *saved
	for _, pair := range []struct{ old, current *string }{
		{&candidate.Work, &current.Work}, {&candidate.Trust, &current.Trust}, {&candidate.Keys, &current.Keys},
		{&candidate.Image, &current.Image}, {&candidate.Platform, &current.Platform},
	} {
		if *pair.old == "" {
			*pair.old = *pair.current
		}
	}
	if !reflect.DeepEqual(candidate, current) {
		return false
	}
	*saved = candidate
	return true
}

// ensureOfflineSigningProfile makes the guided workflow self-contained. The
// profile is only created when absent; each later signing action still checks
// that its public folders and release match before it can run.
func ensureOfflineSigningProfile(p guidedProfile, root string) error {
	alias := offlineRoleAlias(p.Name, p.Role)
	dir, err := guidedDirectory(root, alias, "decision-signer")
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, "profile.json")); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	image := p.Image
	if p.ReleaseCommit == "" && image == "" && p.Role == "participant" {
		config, err := loadRoleConfig(p.Config, "participant")
		if err != nil {
			return err
		}
		image = config.DockerImage
	}
	args := []string{alias, "--settings-root", root, "--role", "decision-signer", "--work", p.Work, "--trust", p.Trust, "--keys", p.Keys}
	if p.ReleaseCommit != "" {
		args = append(args, "--release", "role-images-"+p.ReleaseCommit)
	} else {
		args = append(args, "--image", image, "--download=false")
	}
	fmt.Fprintln(os.Stdout, "Preparing the required network-disabled signing profile for this guided workflow.")
	return runGuidedSetup(args)
}

func saveJSONAtomic(path string, value any) error {
	// Private, fsynced replacement; callers hold the workflow lock.
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 {
		return errors.New("workflow history reached its size limit; preserve it and review archival/recovery with a maintainer before further actions")
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".flow-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validateFlowValue(field flowField, value string) error {
	if value == "" && field.Optional {
		return nil
	}
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("enter a nonempty single-line value")
	}
	if len(field.Choices) != 0 {
		found := false
		for _, choice := range field.Choices {
			found = found || choice == value
		}
		if !found {
			return errors.New("choose one of the displayed options")
		}
	}
	switch field.Kind {
	case "path":
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || !(strings.HasPrefix(value, "/work/") || strings.HasPrefix(value, "/trust/") || strings.HasPrefix(value, "/keys/")) {
			return errors.New("use a path under /work, /trust or /keys without .. components")
		}
	case "host":
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return errors.New("use an absolute local path")
		}
	case "time":
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			return errors.New("use an RFC3339 timestamp, for example 2026-09-08T12:00:00Z")
		}
	case "number":
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 {
			return errors.New("enter a positive whole number")
		}
	}
	return nil
}

func (f *roleFlow) command(task flowTask) ([]string, error) {
	command := append([]string(nil), task.Command...)
	fields := append([]flowField(nil), task.Fields...)
	if len(task.ExtraFields) > 0 {
		key := f.stages[f.state.Stage].ID + "/" + task.ID + "/extra-count"
		current := "0"
		if saved, ok := f.state.Values[key]; ok {
			current = saved
		}
		for {
			value, err := f.ui.ask(task.ExtraLabel+" (0 if none)", current)
			if err != nil {
				return nil, err
			}
			count, err := strconv.Atoi(value)
			if err != nil || count < 0 || count > 253 {
				fmt.Fprintln(f.ui.output, "Enter a number from 0 to 253.")
				continue
			}
			f.state.Values[key] = value
			for i := 0; i < count; i++ {
				fields = append(fields, task.ExtraFields...)
			}
			break
		}
	}
	for index, field := range fields {
		key := f.stages[f.state.Stage].ID + "/" + task.ID + "/" + strconv.Itoa(index) + "/" + field.Flag
		current := field.Default
		if f.state.Role == "participant" && field.Flag == "config" && current == "" && filepath.Base(f.state.Profile.Config) == "participant-phase1.json" {
			phase := f.stages[f.state.Stage].ID
			if phase == "phase1" || phase == "phase2" {
				current = filepath.Join(filepath.Dir(f.state.Profile.Config), "participant-"+phase+".json")
			}
		}
		if shared, ok := f.state.Values["shared/"+field.Flag]; ok {
			current = shared
		}
		if saved, ok := f.state.Values[key]; ok && field.Kind != "time" {
			current = saved
		}
		authenticatedHead := ""
		if phase := flowHeadPhase(field); phase != "" && f.state.Profile.Work != "" {
			head, err := f.discoverHead(phase, command)
			if err != nil {
				return nil, err
			}
			head, err = f.chooseMirrorHead(task, head)
			if err != nil {
				return nil, err
			}
			current = flowContainerPath(f.state.Profile, head.Chain.ChainPath)
			authenticatedHead = current
		}
		if strings.HasSuffix(field.Flag, "chain-signature") {
			if chain := commandValue(command, strings.TrimSuffix(field.Flag, "-signature")); strings.HasSuffix(chain, ".json") {
				current = strings.TrimSuffix(chain, ".json") + ".sig"
			}
		}
		if task.ID == "draft-receipt" && field.Flag == "index" {
			var checkpoint flowHeadCheckpoint
			if raw := f.state.Values["head/"+f.stages[f.state.Stage].ID]; raw != "" {
				if err := json.Unmarshal([]byte(raw), &checkpoint); err != nil {
					return nil, err
				}
				if checkpoint.Count > 0 {
					current = strconv.Itoa(checkpoint.Count)
				}
			}
			if selected := f.state.Values["mirror-index/"+f.stages[f.state.Stage].ID]; selected != "" {
				current = selected
			}
		}
		if current == "NOW" {
			current = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if flowIndependentOutput(task, field) {
			var err error
			current = f.rememberedOutputPath(current, false)
			current, err = f.freshOutputDefault(current)
			if err != nil {
				return nil, err
			}
		} else if field.Kind == "path" {
			current = f.rememberedOutputPath(current, true)
		}
		identities, err := f.identityChoices(task, field)
		if err != nil {
			return nil, fmt.Errorf("read local public identity choices: %w", err)
		}
		schedule, expectedParticipant, err := f.scheduledTurnParticipant(task, field)
		if err != nil {
			return nil, fmt.Errorf("read authenticated participant order: %w", err)
		}
		if expectedParticipant != "" {
			current = expectedParticipant
			fmt.Fprintln(f.ui.output, "Authenticated participant order:")
			for _, choice := range schedule {
				fmt.Fprintf(f.ui.output, "  %s\n", choice.label)
			}
			fmt.Fprintln(f.ui.output, "Relay fills the expected next participant from that signed schedule. It is not editable; stop and investigate if it is unexpected.")
		}
		if value, fixed := fixedWorkflowValue(task, field); fixed {
			// A recipe-fixed value is shown for
			// review but never asks the operator to translate a menu number into
			// a protocol value.
			fmt.Fprintf(f.ui.output, "%s: %s (fixed by workflow)\n", field.Label, value)
			f.state.Values[key] = value
			command = append(command, "--"+field.Flag, value)
			continue
		}
		var grantRange flowGrantLimits
		var grantTTL time.Duration
		if field.Flag == "credential-ttl" || field.Flag == "minimum-remaining" {
			grantRange, err = f.grantLimits(command)
			if err != nil {
				return nil, err
			}
			if grantRange.maximum > 0 {
				grantTTL, _ = time.ParseDuration(commandValue(command, "credential-ttl"))
				if grantTTL == 0 {
					grantTTL = grantRange.maximum
				}
				current = grantRange.defaultValue(field.Flag, current, grantTTL)
				if field.Flag == "minimum-remaining" {
					fmt.Fprintln(f.ui.output, "This is the time that must still be left when work starts, not extra time added to the grant. Leave time for delivery and setup.")
				}
			}
		}
		for {
			label := field.Label
			if grantRange.maximum > 0 {
				label = grantRange.label(field.Flag, label, grantTTL)
			}
			if field.Optional {
				label += " (optional; - to omit)"
			}
			var value string
			var err error
			if expectedParticipant != "" {
				value = expectedParticipant
				fmt.Fprintf(f.ui.output, "%s: %s (authenticated next participant)\n", label, value)
			} else if len(identities) > 0 {
				fmt.Fprintln(f.ui.output, "Names below come from your saved public identities, not proof of assignment or whose turn it is. Check the authenticated schedule before issuing a grant.")
				value, err = f.ui.choose(label, current, identities)
			} else if len(field.Choices) != 0 {
				choices := []setupChoice{}
				for _, choice := range field.Choices {
					choices = append(choices, setupChoice{value: choice, label: choice})
				}
				value, err = f.ui.choose(label, current, choices)
			} else {
				displayed := current
				if field.Kind == "path" {
					displayed = flowHostPath(f.state.Profile, current)
				}
				value, err = f.ui.ask(label, displayed)
			}
			if err != nil {
				return nil, err
			}
			if field.Optional && value == "-" {
				value = ""
			}
			if field.Kind == "path" && value != "" {
				value = flowContainerPath(f.state.Profile, value)
			}
			if err := validateFlowValue(field, value); err != nil {
				fmt.Fprintln(f.ui.output, err)
				continue
			}
			if grantRange.maximum > 0 {
				if err := grantRange.validate(field.Flag, value, grantTTL); err != nil {
					fmt.Fprintln(f.ui.output, err)
					continue
				}
			}
			if authenticatedHead != "" && value != authenticatedHead {
				fmt.Fprintln(f.ui.output, "Use the authenticated local head shown above. Resolve missing or conflicting transcript files before continuing; historical inspection is a separate read-only action.")
				continue
			}
			f.state.Values[key] = value
			switch field.Flag {
			case "ceremony", "ceremony-signature", "coordinator-public-key-file", "transcript-root", "transcript-dir", "coordinator-signing-key", "storage", "phase1-seal", "phase1-seal-signature":
				f.state.Values["shared/"+field.Flag] = value
			}
			if value != "" {
				command = append(command, "--"+field.Flag, value)
			}
			break
		}
	}
	return command, checkSavedCommand(command)
}

func flowContainerPath(p guidedProfile, value string) string {
	if filepath.Clean(value) != value {
		return value
	}
	for _, mount := range []struct{ host, container string }{{p.Work, "/work"}, {p.Trust, "/trust"}, {p.Keys, "/keys"}} {
		if mount.host != "" && strings.HasPrefix(value, mount.host+"/") {
			return mount.container + strings.TrimPrefix(value, mount.host)
		}
	}
	return value
}

// Display host paths without changing the fixed, validated Docker command paths.
func flowHostPath(p guidedProfile, value string) string {
	if filepath.Clean(value) != value {
		return value
	}
	for _, mount := range []struct{ host, container string }{{p.Work, "/work"}, {p.Trust, "/trust"}, {p.Keys, "/keys"}} {
		if mount.host != "" && strings.HasPrefix(value, mount.container+"/") {
			return mount.host + strings.TrimPrefix(value, mount.container)
		}
	}
	return value
}

func (f *roleFlow) last(task flowTask) *flowAttempt {
	// An unresolved older turn must not disappear merely because local head
	// discovery moved the menu to a newer scope.
	seenOperations := map[string]bool{}
	for n := len(f.state.Attempts) - 1; n >= 0; n-- {
		a := &f.state.Attempts[n]
		if seenOperations[a.ID] {
			continue
		}
		seenOperations[a.ID] = true
		if a.Task == task.ID && a.Stage == f.stages[f.state.Stage].ID && (a.Status == "prepared" || a.Status == "running" || a.Status == "failed" || a.Status == "reviewed-incomplete") {
			return a
		}
	}
	for n := len(f.state.Attempts) - 1; n >= 0; n-- {
		a := &f.state.Attempts[n]
		if a.Task == task.ID && a.Stage == f.stages[f.state.Stage].ID && (f.turnScope == nil || (a.TurnScope != nil && *a.TurnScope == *f.turnScope)) {
			return a
		}
	}
	return nil
}

func (f *roleFlow) execute(task flowTask) error {
	if err := f.requireTaskPredecessors(task); err != nil {
		return err
	}
	if f.state.Role == "coordinator" && task.ID == "enrollment" && f.state.Profile.Work != "" {
		return f.collectEnrollment(task)
	}
	if f.stages[f.state.Stage].ID == "decision" {
		requirement, err := f.decisionRequirement()
		if err != nil {
			return err
		}
		if requirement == "not-applicable" {
			return errors.New("production decision tasks do not apply to this authenticated rehearsal")
		}
	}
	if (task.ID == "turns-complete" || (f.state.Role == "coordinator" && task.ID == "close")) && f.state.Profile.Work != "" {
		if err := f.checkScheduledTurns(); err != nil {
			return err
		}
	}
	fmt.Fprintln(f.ui.output, "\n"+task.Label+"\n"+task.Help)
	previous := f.last(task)
	if previous != nil && previous.Status == "prepared" {
		// The only transition out of prepared is a separately synced running
		// record immediately before f.run. Seeing prepared after restart proves
		// that Relay never invoked the child operation.
		previous.Status = "not-started"
		previous.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
		if err := f.save(); err != nil {
			return err
		}
		fmt.Fprintln(f.ui.output, "The previous action stopped before launch; no command ran. Review this action again to continue.")
		previous = f.last(task)
	}
	if previous != nil {
		adopted, err := f.adoptWrittenGrant(task, previous)
		if err != nil {
			return err
		}
		if adopted {
			return nil
		}
	}
	var savedRecipeErr error
	if previous != nil && len(previous.Command) != 0 {
		savedRecipeErr = validateFlowCommand(task, previous.Command)
	}
	retry := previous != nil && (previous.Status == "running" || previous.Status == "failed" || f.checkAttemptEvidence(previous) != nil || savedRecipeErr != nil)
	var command []string
	id := ""
	if retry {
		var err error
		command, id, retry, err = f.reconcilePrevious(task, previous, savedRecipeErr)
		if err != nil {
			return err
		}
	} else {
		var err error
		if task.Handoff {
			bindings, err := f.handoffBindings(task)
			if err != nil {
				return err
			}
			choice, err := f.ui.choose("Report this specific step: "+task.Label, "", []setupChoice{{"reported", "I completed the human action described above"}, {"waiting", "Not yet — leave this step waiting"}, {"issue", "There is a problem — record it and pause"}})
			if err != nil {
				return err
			}
			if choice == "waiting" {
				return nil
			}
			note := "Operator reported: " + task.Label
			status := "reported"
			if choice == "issue" {
				status = "reviewed-incomplete"
				note, err = f.ui.required("Describe the problem (no secrets)", "")
				if err != nil {
					return err
				}
			} else {
				fmt.Fprintln(f.ui.output, "Recorded as YOUR report, not verified delivery, recipient review, or cryptographic evidence.")
			}
			id, err := randomID()
			if err != nil {
				return err
			}
			if err := f.checkAttemptEvidence(&flowAttempt{InputBindings: bindings}); err != nil {
				return err
			}
			f.state.Attempts = append(f.state.Attempts, flowAttempt{ID: id, Task: task.ID, Stage: f.stages[f.state.Stage].ID, Status: status, Note: note, InputBindings: bindings, TurnScope: f.turnScope, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)})
			return f.save()
		}
		command, err = f.command(task)
		if err != nil {
			return err
		}
		id, err = randomID()
		if err != nil {
			return err
		}
		id = "flow-" + id
		command, err = prepareRecoveryCommand(task, command, id, time.Now())
		if err != nil {
			return err
		}
		if err := f.bindPublicInputs(command); err != nil {
			return fmt.Errorf("required input unavailable; return to setup or import the indicated public files before running: %w", err)
		}
		reviewedInputs, err := f.captureEvidence(task, command)
		if err != nil {
			return err
		}
		directories, err := f.captureDirectories(task, command)
		if err != nil {
			return err
		}
		if err := f.confirmAction(command); err != nil {
			return err
		}
		if err := f.checkAttemptEvidence(&flowAttempt{InputBindings: reviewedInputs}); err != nil {
			return err
		}
		if err := f.checkDirectoryBindings(directories); err != nil {
			return err
		}
		if previous != nil && reflect.DeepEqual(previous.Command, command) && previous.Status == "succeeded" && !flowRepeatable(task) {
			return errors.New("this exact action already completed; use verification to inspect its result, not another write")
		}
	}
	if err := validateFlowCommand(task, command); err != nil {
		return err
	}
	if err := f.bindPublicInputs(command); err != nil {
		return err
	}
	if err := f.checkObservationWindow(task); err != nil {
		return err
	}
	inputBindings, err := f.captureEvidence(task, command)
	if err != nil {
		return err
	}
	directoryBindings, err := f.captureDirectories(task, command)
	if err != nil {
		return err
	}
	receiptScope, err := f.mirrorReceiptScope(task, command)
	if err != nil {
		return err
	}
	image, platform, mounts, expectedOutputs, err := f.recoveryMetadata(task, command)
	if err != nil {
		return err
	}
	// Save a fully resolved intent first. Only a separately synced transition to
	// running permits child execution, so a retained prepared record proves no
	// child was launched and can safely return to normal review.
	f.state.Attempts = append(f.state.Attempts, flowAttempt{ID: id, Task: task.ID, Stage: f.stages[f.state.Stage].ID, Status: "prepared", OperationSchema: flowOperationSchema, RecoveryClass: flowTaskRecoveryClass(task), ImageDigest: image, Platform: platform, Command: append([]string(nil), command...), StartedAt: time.Now().UTC().Format(time.RFC3339Nano), Mounts: mounts, ExpectedOutputs: expectedOutputs, InputBindings: inputBindings, TurnScope: f.turnScope})
	index := len(f.state.Attempts) - 1
	f.state.Attempts[index].ReceiptScope = receiptScope
	f.state.Attempts[index].DirectoryBindings = directoryBindings
	if err := f.save(); err != nil {
		return err
	}
	f.state.Attempts[index].Status = "running"
	if err := f.save(); err != nil {
		return err
	}
	err = f.run(task, command, id, retry)
	if err == nil {
		err = f.checkDirectoryBindings(directoryBindings)
	}
	if err == nil {
		// Some commands append authenticated transcript artifacts. Record their
		// resulting tree rather than treating those expected writes as tampering.
		f.state.Attempts[index].DirectoryBindings, err = f.captureDirectories(task, command)
	}
	if err == nil && receiptScope != nil && task.ID == "sign-receipt" {
		value := commandValue(command, "out")
		var local, digest string
		local, err = f.publicHostPath(value)
		if err == nil {
			digest, err = setupFileHash(local)
		}
		if err == nil {
			f.state.Attempts[index].InputBindings[value] = digest
			f.state.Attempts[index].ReceiptScope.SignatureDigest = digest
		}
	}
	if err == nil {
		err = f.checkAttemptEvidence(&f.state.Attempts[index])
	}
	if err == nil {
		err = f.bindSuccessfulOutputs(task, command, &f.state.Attempts[index])
	}
	f.state.Attempts[index].Status = "succeeded"
	if err != nil {
		f.state.Attempts[index].Status = "failed"
	} else {
		f.rememberSuccessfulOutputs(task, command)
	}
	f.state.Attempts[index].FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if saveErr := f.save(); saveErr != nil {
		return saveErr
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(f.ui.output, "Command completed. Its output describes what was verified; upload alone is not acceptance.")
	return nil
}

func (f *roleFlow) bindPublicInputs(command []string) error {
	if f.state.Profile.Work == "" {
		return nil
	} // injected test runner without mounts
	if f.state.PublicBindings == nil {
		f.state.PublicBindings = map[string]string{}
	}
	// Relay transport commands carry trust paths inside their profiles, not
	// directly in argv. Bind those to the same ceremony as proof-tool actions.
	inputs := append([]string(nil), command...)
	if len(command) > 0 && command[0] == "relay" {
		for n, arg := range command {
			if n+1 >= len(command) || (arg != "--storage" && arg != "--config") {
				continue
			}
			local, err := f.publicHostPath(command[n+1])
			if err != nil {
				return err
			}
			var ceremony, signature, key string
			if arg == "--storage" {
				var config access.StorageConfig
				if err := setupReadJSON(local, &config); err != nil {
					return err
				}
				if err := config.Validate(); err != nil {
					return err
				}
				ceremony, signature, key = config.CeremonyPath, config.CeremonySignature, config.CoordinatorPublicKey
			} else {
				var config access.RoleConfig
				if err := setupReadJSON(local, &config); err != nil {
					return err
				}
				if err := config.Validate(); err != nil {
					return err
				}
				ceremony, signature, key = config.Ceremony, config.CeremonySignature, config.CoordinatorKey
			}
			inputs = append(inputs, "--ceremony", ceremony, "--ceremony-signature", signature, "--coordinator-public-key-file", key)
		}
	}
	for n, arg := range inputs {
		if n+1 >= len(inputs) || (arg != "--ceremony" && arg != "--ceremony-signature" && arg != "--coordinator-public-key-file") {
			continue
		}
		local, err := f.publicHostPath(inputs[n+1])
		if err != nil {
			return err
		}
		digest, err := setupFileHash(local)
		if err != nil {
			return err
		}
		if previous, ok := f.state.PublicBindings[arg]; ok && previous != digest {
			return errors.New("ceremony or coordinator trust input changed; do not reuse another ceremony's workflow progress")
		}
		f.state.PublicBindings[arg] = digest
	}
	return nil
}

func (f *roleFlow) publicHostPath(value string) (string, error) {
	if err := validateFlowValue(flowField{Kind: "path"}, value); err != nil {
		return "", err
	}
	for _, mount := range []struct{ container, host string }{{"/work", f.state.Profile.Work}, {"/trust", f.state.Profile.Trust}} {
		if mount.host != "" && strings.HasPrefix(value, mount.container+"/") {
			root, err := filepath.EvalSymlinks(mount.host)
			if err != nil {
				return "", err
			}
			relative := strings.TrimPrefix(value, mount.container+"/")
			current := root
			for _, component := range strings.Split(relative, "/") {
				current = filepath.Join(current, component)
				st, err := os.Lstat(current)
				if errors.Is(err, os.ErrNotExist) {
					break
				}
				if err != nil {
					return "", err
				}
				if st.Mode()&os.ModeSymlink != 0 {
					return "", errors.New("public evidence paths must not contain symlinks")
				}
			}
			return filepath.Join(root, relative), nil
		}
	}
	return "", errors.New("public ceremony/trust inputs must be inside your work or trust folder")
}

func flowRepeatable(task flowTask) bool {
	c := task.Command
	if len(c) > 2 && c[0] == "relay" && c[1] == "coordinator" && c[2] == "grant" {
		return true
	}
	if len(c) > 0 && c[0] == "status" {
		return true
	}
	if len(c) > 1 && c[0] == "mpc-ceremony" && c[1] == "inspect" {
		return true
	}
	if len(c) > 2 && c[0] == "mpc-ceremony" && c[2] == "verify" && (c[1] == "release" || c[1] == "ops" || c[1] == "decision") {
		return true
	}
	return len(c) > 2 && c[0] == "relay" && (c[2] == "run" || c[2] == "candidates" || c[2] == "evidence")
}

func fixedWorkflowValue(task flowTask, field flowField) (string, bool) {
	if (task.ID == "prepare-outbound-handoff" || task.ID == "prepare-return-handoff") && field.Flag == "direction" {
		return field.Default, true
	}
	return "", false
}

// Persisted commands are data, never an escape hatch into arbitrary CLI actions.
func validateFlowCommand(task flowTask, command []string) error {
	if len(command) < len(task.Command) || !reflect.DeepEqual(command[:len(task.Command)], task.Command) {
		return errors.New("saved command differs from this workflow recipe")
	}
	args := command[len(task.Command):]
	for _, field := range task.Fields {
		if len(args) < 2 || args[0] != "--"+field.Flag {
			if field.Optional {
				continue
			}
			return fmt.Errorf("saved command is missing --%s", field.Flag)
		}
		if expected, fixed := fixedWorkflowValue(task, field); fixed && args[1] != expected {
			return fmt.Errorf("saved command has --%s %q; this workflow requires %q", field.Flag, args[1], expected)
		}
		if err := validateFlowValue(field, args[1]); err != nil {
			return err
		}
		args = args[2:]
	}
	if len(task.ExtraFields) > 0 {
		groups := 0
		for len(args) > 0 {
			groups++
			if groups > 253 {
				return errors.New("too many additional evidence inputs")
			}
			for _, field := range task.ExtraFields {
				if len(args) < 2 || args[0] != "--"+field.Flag {
					return errors.New("incomplete additional evidence group")
				}
				if err := validateFlowValue(field, args[1]); err != nil {
					return err
				}
				args = args[2:]
			}
		}
	}
	if flowTaskRecoveryClass(task) == recoveryUpload {
		// The authored catalog recipe has no allocated identity yet. A persisted
		// invocation always does; recovery separately rejects legacy uploads that
		// lack it.
		if len(args) == 0 {
			return checkSavedCommand(command)
		}
		if len(args) != 4 || args[0] != "--attempt-id" || args[2] != "--completed-at" {
			return errors.New("saved upload command is missing its stable attempt identity")
		}
		if !validFlowAttemptID(args[1]) {
			return errors.New("saved upload attempt ID is invalid")
		}
		if _, err := time.Parse(time.RFC3339, args[3]); err != nil {
			return errors.New("saved upload completion time is invalid")
		}
		args = args[4:]
	}
	if flowTaskRecoveryClass(task) == recoveryDocker && task.ID == "contribute" {
		if len(args) == 0 {
			// Compatibility with operations saved before guided and participant
			// attempt identities were unified. Recovery never invents this value.
			return checkSavedCommand(command)
		}
		if len(args) != 2 || args[0] != "--attempt-id" || !validFlowAttemptID(args[1]) {
			return errors.New("saved participant command has an invalid stable attempt identity")
		}
		args = args[2:]
	}
	if len(args) != 0 {
		return errors.New("unexpected saved command arguments")
	}
	return checkSavedCommand(command)
}

func (f *roleFlow) advance() error {
	if err := f.checkMirrorCoverage(); err != nil {
		return err
	}
	if f.state.Profile.Work != "" && f.state.Role == "coordinator" && f.stages[f.state.Stage].ID == "enrollments" {
		complete, err := f.collectedEnrollments()
		if err != nil {
			return err
		}
		if !complete {
			return errors.New("required enrollment collection is incomplete; import the missing public records and resolve verification failures")
		}
	}
	if f.state.Profile.Work != "" && f.state.Role == "coordinator" && strings.HasSuffix(f.stages[f.state.Stage].ID, "-turns") {
		if err := f.checkScheduledTurns(); err != nil {
			return err
		}
	}
	decisionRequired := false
	if f.stages[f.state.Stage].ID == "decision" {
		requirement, err := f.decisionRequirement()
		if err != nil {
			return err
		}
		if requirement == "not-applicable" {
			fmt.Fprintln(f.ui.output, "Production decision omitted: the authenticated definition selects rehearsal mode. This is not a production authorization.")
			f.state.Stage++
			return f.save()
		}
		decisionRequired = true
	}
	for _, task := range f.stages[f.state.Stage].Tasks {
		last := f.last(task)
		if err := f.checkAttemptEvidence(last); err != nil {
			return err
		}
		if last != nil && (last.Status == "running" || last.Status == "failed") {
			return errors.New("resolve the interrupted/failed action before moving on")
		}
		if (decisionRequired || !task.Optional) && (last == nil || (last.Status != "succeeded" && !(task.Handoff && last.Status == "reported"))) {
			return fmt.Errorf("complete %q first", task.Label)
		}
	}
	if err := f.ui.confirm("Move to the next stage? Local progress is not proof of ceremony acceptance", "CONTINUE"); err != nil {
		return err
	}
	f.state.Stage++
	return f.save()
}

func (f *roleFlow) stageMenu() error {
	for {
		if f.state.Stage == len(f.stages) {
			fmt.Fprintln(f.ui.output, "End of the selected ceremony areas. Review recorded results and any unfinished earlier work; reaching this screen does not establish ceremony completion or release authorization.")
			f.ui.message(toneMuted, "\nNAVIGATION\n")
			fmt.Fprintln(f.ui.output, "  [M] Ceremony map\n  [B] Back to previous view\n  [Q] Save and exit")
			choice, err := f.ui.ask("Choose", "0")
			if err == io.EOF || strings.EqualFold(choice, "q") || choice == "0" {
				return f.save()
			}
			if err != nil {
				return err
			}
			if strings.EqualFold(choice, "b") {
				if err := f.goBack(); err != nil {
					f.ui.message(toneError, "Paused: %v\n", err)
				}
				return nil
			}
			if !strings.EqualFold(choice, "m") {
				fmt.Fprintln(f.ui.output, "Choose a displayed letter.")
				continue
			}
			if _, err := f.ceremonyMap(); err != nil {
				return err
			}
			return nil
		}
		stage := f.stages[f.state.Stage]
		if err := f.prepareCurrentTurnScope(stage); err != nil {
			f.ui.message(toneWarning, "Waiting: %v\n", err)
		}
		decisionState := ""
		if stage.ID == "decision" {
			var err error
			decisionState, err = f.decisionRequirement()
			if err != nil {
				fmt.Fprintf(f.ui.output, "Waiting: %v\n", err)
			}
		}
		f.ui.message(toneHeading, "\nRELAY | %s | %s\n------------------------------------------------------------\n%s (%d/%d)\n", strings.ToUpper(f.state.Role), f.state.Name, stage.Label, f.state.Stage+1, len(f.stages))
		f.showCurrentPhase()
		if stage.ID != "decision" || decisionState != "" {
			hidden := decisionState == "not-applicable"
			if n := f.firstUnfinishedRequiredTask(stage, hidden); n >= 0 {
				task := stage.Tasks[n]
				if a := f.last(task); a != nil && (a.Status == "running" || a.Status == "failed") {
					fmt.Fprintf(f.ui.output, "Needs attention: %d — %s. Review the retained attempt before retrying.\n", n+1, task.Label)
				} else {
					fmt.Fprintf(f.ui.output, "Suggested next step: %d — %s. This is the next authored workflow action; readiness only explains whether it is waiting.\n", n+1, task.Label)
				}
			}
		}
		for n, task := range stage.Tasks {
			if decisionState == "not-applicable" {
				break
			}
			status := "Not yet run; prerequisites will be checked"
			if a := f.last(task); a != nil {
				switch a.Status {
				case "reported":
					status = "Handoff reported — not verified"
				case "succeeded":
					status = "Command completed — see verification output"
				case "running", "failed":
					status = "Needs attention — inspect retained output"
				default:
					status = "Waiting — reported problem unresolved"
				}
				if a.FinishedAt != "" {
					status += " (" + a.FinishedAt + ")"
				}
				if err := f.checkAttemptEvidence(a); err != nil {
					status = "Needs attention — " + err.Error()
				}
			}
			readiness := f.readiness(task)
			status = readiness.summary()
			kind := readiness.Requirement
			if stage.ID == "decision" && decisionState == "" {
				kind = "Waiting for authenticated ceremony mode"
			}
			fmt.Fprintf(f.ui.output, "\n%d) %s [%s]\n   Why: %s\n   Status: %s\n", n+1, task.Label, kind, taskWhy(task, readiness), status)
		}
		if decisionState == "not-applicable" {
			fmt.Fprintln(f.ui.output, "Production decision actions hidden: not applicable to this authenticated rehearsal.")
		}
		nextLabel := "Review role completion and retention"
		if f.state.Stage+1 < len(f.stages) {
			nextLabel = "Open " + f.stages[f.state.Stage+1].Label
		}
		f.ui.message(toneSuccess, "\nWORKFLOW ACTION\n")
		fmt.Fprintf(f.ui.output, "  %d) %s\n", len(stage.Tasks)+1, nextLabel)
		f.ui.message(toneMuted, "\nNAVIGATION\n")
		fmt.Fprintln(f.ui.output, "  [B] Back to overview\n  [M] Ceremony map\n  [Q] Save and exit")
		choice, err := f.ui.ask("Choose", "0")
		if err == io.EOF || strings.EqualFold(choice, "q") || choice == "0" {
			return f.save()
		}
		if err != nil {
			return err
		}
		if strings.EqualFold(choice, "b") {
			return nil
		}
		if strings.EqualFold(choice, "m") {
			if _, err := f.ceremonyMap(); err != nil {
				return err
			}
			return nil
		}
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(stage.Tasks)+1 {
			fmt.Fprintln(f.ui.output, "Choose a displayed number.")
			continue
		}
		switch n {
		case len(stage.Tasks) + 1:
			err = f.advance()
		default:
			err = f.execute(stage.Tasks[n-1])
		}
		if err != nil {
			f.ui.message(toneError, "Paused: %v\n", err)
			fmt.Fprintln(f.ui.output, "Files and progress retained. Do not bypass verification.")
		}
	}
}

func runRoleFlow(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: relay ceremony guide NAME --role ROLE [--settings-root DIR]")
	}
	root, err := guidedRoot()
	if err != nil {
		return err
	}
	flags := flag.NewFlagSet("ceremony guide", flag.ContinueOnError)
	role := flags.String("role", "", "coordinator, participant, witness, mirror, auditor, release-signer, or upload-station")
	flags.StringVar(&root, "settings-root", root, "saved settings root")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return errors.New("unexpected arguments")
	}
	dir, err := guidedDirectory(root, args[0], *role)
	if err != nil {
		return err
	}
	p, err := readGuidedProfile(filepath.Join(dir, "profile.json"), args[0], *role)
	if err != nil {
		return fmt.Errorf("save your role settings with ceremony setup first: %w", err)
	}
	if len(p.Command) != 0 {
		return errors.New("guide requires shared settings saved without a command; keep existing named actions for recovery")
	}
	if err := checkLauncherRelease(p.ReleaseCommit); err != nil {
		return err
	}
	stages := roleFlowStages(*role)
	if len(stages) == 0 {
		return errors.New("no guided workflow for this role")
	}
	if flowNeedsOfflineSigner(stages) {
		if err := ensureOfflineSigningProfile(p, root); err != nil {
			return fmt.Errorf("prepare the network-disabled signing profile before guided work: %w", err)
		}
	}
	if err := ensurePrivateDirectory(filepath.Join(dir, "workflow")); err != nil {
		return err
	}
	statePath := filepath.Join(dir, "workflow", "state.json")
	lock, err := acquireParticipantRunLock(statePath, filepath.Dir(statePath))
	if err != nil {
		return err
	}
	defer lock.release()
	p, err = readGuidedProfile(filepath.Join(dir, "profile.json"), args[0], *role)
	if err != nil {
		return err
	}
	if len(p.Command) != 0 {
		return errors.New("saved settings changed to a single action; reopen the matching workflow settings")
	}
	if err := checkLauncherRelease(p.ReleaseCommit); err != nil {
		return err
	}
	catalogBytes, err := json.Marshal(stages)
	if err != nil {
		return err
	}
	catalogDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(catalogBytes))
	f := roleFlow{state: roleFlowState{Schema: roleFlowSchema, Name: p.Name, Role: p.Role, CatalogDigest: catalogDigest, Profile: p, Values: map[string]string{}}, stages: stages, path: statePath, settingsRoot: root, ui: coordinatorWizard{input: bufio.NewReader(os.Stdin), output: os.Stdout}}
	if p.Role == "coordinator" {
		if st, err := os.Lstat(filepath.Join(p.Trust, "setup-coordinator.hex")); err == nil && st.Mode().IsRegular() {
			f.state.Values["shared/coordinator-public-key-file"] = "/trust/setup-coordinator.hex"
		}
	}
	stateExisted := false
	if _, err := os.Lstat(statePath); err == nil {
		stateExisted = true
		if err := setupReadJSON(statePath, &f.state); err != nil {
			return err
		}
		profileMatches := reflect.DeepEqual(f.state.Profile, p) || normalizeSavedParticipantProfile(&f.state.Profile, p)
		if (f.state.Schema != roleFlowSchemaV1 && f.state.Schema != roleFlowSchema) || f.state.Name != p.Name || f.state.Role != p.Role || !profileMatches || f.state.Stage < 0 || f.state.Values == nil {
			return errors.New("workflow does not match saved role settings")
		}
		if err := migrateFlowCatalog(statePath, catalogDigest, stages, &f.state); err != nil {
			return err
		}
		if f.state.Stage < 0 || f.state.Stage > len(stages) {
			return errors.New("saved workflow stage is outside this release's catalog")
		}
		for _, index := range f.state.ViewHistory {
			if index < 0 || index >= len(stages) {
				return errors.New("workflow navigation history is invalid; preserve the workflow folder and contact the coordinator")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := ensureFlowWorkspace(statePath, p, &f.state, stateExisted); err != nil {
		return err
	}
	if p.Role == "participant" {
		digest, err := setupFileHash(p.Config)
		if err != nil {
			return err
		}
		if f.state.PublicBindings == nil {
			f.state.PublicBindings = map[string]string{}
		}
		if old, ok := f.state.PublicBindings["participant-profile"]; ok && old != digest {
			return errors.New("the saved participant profile changed; do not reuse another assignment's progress")
		}
		f.state.PublicBindings["participant-profile"] = digest
	}
	f.run = func(task flowTask, command []string, id string, retry bool) error {
		open := []string{"ceremony", "open", p.Name, "--role", p.Role, "--settings-root", root}
		if task.Offline {
			alias := offlineRoleAlias(p.Name, p.Role)
			dir, err := guidedDirectory(root, alias, "decision-signer")
			if err != nil {
				return err
			}
			offline, err := readGuidedProfile(filepath.Join(dir, "profile.json"), alias, "decision-signer")
			if err != nil {
				return fmt.Errorf("prepare the network-disabled signing image in onboarding first: %w", err)
			}
			if offline.Work != p.Work || offline.Trust != p.Trust || offline.Keys == "" || offline.Credentials != "" || offline.ReleaseCommit != p.ReleaseCommit || len(offline.Command) != 0 {
				return errors.New("network-disabled signing profile does not match this role's public folders and release")
			}
			if len(command) >= 3 && command[0] == "mpc-ceremony" && command[1] == "ops" && command[2] == "sign" {
				digest, err := f.reviewOfflineRecord(command)
				if err != nil {
					return err
				}
				command = append(append([]string(nil), command...), "--reviewed-sha256", digest)
			}
			open = []string{"ceremony", "open", alias, "--role", "decision-signer", "--settings-root", root}
		}
		if p.Role == "participant" && !task.Offline {
			configPath := ""
			participantArgs := []string{command[0]}
			for n := 1; n < len(command); n += 2 {
				if n+1 >= len(command) {
					return errors.New("participant workflow command has an incomplete flag")
				}
				if command[n] == "--config" {
					configPath = command[n+1]
				} else {
					participantArgs = append(participantArgs, command[n:n+2]...)
				}
			}
			base, err := loadRoleConfig(p.Config, "participant")
			if err != nil {
				return err
			}
			config, err := loadRoleConfig(configPath, "participant")
			if err != nil {
				return err
			}
			if config.ExecutionMode != dockerExecutionMode || config.DockerImage != base.DockerImage || config.DockerPlatform != base.DockerPlatform || config.IdentityID != base.IdentityID || config.CeremonyID != base.CeremonyID || config.Phase != f.stages[f.state.Stage].ID {
				return errors.New("phase profile does not match this participant, ceremony, approved Docker runtime, and phase")
			}
			open = append([]string{"role", "--role", "participant", "--config", configPath, "--"}, participantArgs...)
		} else {
			open = append(open, "--action", id)
			if retry {
				open = append(open, "--reviewed-retry")
			}
			open = append(append(open, "--"), command...)
		}
		// Retain the workflow lock until the child has handled cancellation and
		// completed its cleanup. CommandContext would kill it before its defers.
		return executeGuidedChild(open)
	}
	fmt.Fprintln(os.Stdout, "Saved progress is a local checklist, not authenticated ceremony state. Other people act on their own machines. Commands still verify exact signed inputs.\nUse /work for staged files, /trust for independently authenticated public keys, /keys for your own signing key. Never paste secret contents.")
	fmt.Fprintf(os.Stdout, "Your folders: /work = %s; /trust = %s; /keys = %s\nYou may enter host paths inside these folders; the guide maps them into Docker.\n", p.Work, p.Trust, p.Keys)
	return f.menu()
}
