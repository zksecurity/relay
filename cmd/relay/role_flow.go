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

const roleFlowSchema = "relay-role-flow-v1"

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
	Command                 []string
	StartedAt, FinishedAt   string
	Note                    string
	InputBindings           map[string]string `json:",omitempty"`
	DirectoryBindings       map[string]string `json:",omitempty"`
	ReceiptScope            *flowReceiptScope `json:",omitempty"`
}
type roleFlowState struct {
	Schema, Name, Role string
	CatalogDigest      string
	Profile            guidedProfile
	Stage              int
	Values             map[string]string
	Attempts           []flowAttempt
	PublicBindings     map[string]string
}
type roleFlow struct {
	state      roleFlowState
	stages     []flowStage
	path       string
	ui         coordinatorWizard
	run        func(flowTask, []string, string, bool) error
	definition func() (transcript.Definition, error)
}

func (f *roleFlow) save() error { return saveJSONAtomic(f.path, f.state) }

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
	return os.Rename(name, path)
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
		var grantMaximum, grantTTL time.Duration
		if field.Flag == "credential-ttl" || field.Flag == "minimum-remaining" {
			grantMaximum, err = f.awsGrantMaximum(command)
			if err != nil {
				return nil, err
			}
			if grantMaximum > 0 {
				grantTTL, _ = time.ParseDuration(commandValue(command, "credential-ttl"))
				if grantTTL == 0 {
					grantTTL = grantMaximum
				}
				current = grantDurationDefault(field.Flag, current, grantMaximum, grantTTL)
			}
		}
		for {
			label := field.Label
			if field.Optional {
				label += " (optional; - to omit)"
			}
			var value string
			var err error
			if len(identities) > 0 {
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
			if grantMaximum > 0 {
				if err := validateAWSGrantDuration(field.Flag, value, grantMaximum, grantTTL); err != nil {
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
	for n := len(f.state.Attempts) - 1; n >= 0; n-- {
		a := &f.state.Attempts[n]
		if a.Task == task.ID && a.Stage == f.stages[f.state.Stage].ID {
			return a
		}
	}
	return nil
}

func (f *roleFlow) execute(task flowTask) error {
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
	retry := previous != nil && (previous.Status == "running" || previous.Status == "failed" || f.checkAttemptEvidence(previous) != nil)
	var command []string
	id := ""
	if retry {
		fmt.Fprintf(f.ui.output, "Previous attempt may have written output: %s\n", previous.ID)
		writeActionSummary(f.ui.output, f.state.Profile, previous.Command)
		choices := []setupChoice{{value: "retry", label: "Retry the exact saved action"}, {value: "resolve", label: "Record investigation; prepare a corrected/resume action next"}}
		if f.state.Role != "participant" && !task.Handoff {
			choices = append(choices, setupChoice{value: "external", label: "Record completion already verified outside this guide"})
		}
		choices = append(choices, setupChoice{value: "inspect", label: "Return to inspect existing outputs before deciding"})
		choice, err := f.ui.choose("Recovery — no automatic retry", "", choices)
		if err != nil {
			return err
		}
		if choice == "inspect" {
			return nil
		}
		if choice == "resolve" || choice == "external" {
			note, err := f.ui.required("What did you verify? Record retained outputs and the recovery decision, never secrets", "")
			if err != nil {
				return err
			}
			message, phrase, status := "This does NOT mark the task successful. Keep existing outputs; for participants use resume-candidate instead of recomputing", "REVIEWED", "reviewed-incomplete"
			if choice == "external" {
				message, phrase, status = "Only if the exact intended outputs were independently verified. This records YOUR report, not a verifier result or a waiver of any protocol check", "RECOVERY VERIFIED", "reported"
			}
			if err := f.ui.confirm(message, phrase); err != nil {
				return err
			}
			recoveryID, err := randomID()
			if err != nil {
				return err
			}
			f.state.Attempts = append(f.state.Attempts, flowAttempt{ID: recoveryID, Task: task.ID, Stage: f.stages[f.state.Stage].ID, Status: status, Note: "Recovery of " + previous.ID + ": " + note, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)})
			return f.save()
		}
		if err := f.ui.confirm("Inspect existing outputs and authenticated heads first. Retrying preserves the exact command", "REVIEWED RETRY"); err != nil {
			return err
		}
		command, id = previous.Command, previous.ID
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
			f.state.Attempts = append(f.state.Attempts, flowAttempt{ID: id, Task: task.ID, Stage: f.stages[f.state.Stage].ID, Status: status, Note: note, InputBindings: bindings, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)})
			return f.save()
		}
		command, err = f.command(task)
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
		id, err = randomID()
		if err != nil {
			return err
		}
		id = "flow-" + id
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
	// Persist before invoking Docker. A crash is an uncertain attempt, not success.
	f.state.Attempts = append(f.state.Attempts, flowAttempt{ID: id, Task: task.ID, Stage: f.stages[f.state.Stage].ID, Status: "running", Command: append([]string(nil), command...), StartedAt: time.Now().UTC().Format(time.RFC3339Nano), InputBindings: inputBindings})
	index := len(f.state.Attempts) - 1
	f.state.Attempts[index].ReceiptScope = receiptScope
	f.state.Attempts[index].DirectoryBindings = directoryBindings
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
			fmt.Fprintln(f.ui.output, "1) Review an earlier stage\n0) Save and exit")
			choice, err := f.ui.ask("Choose", "0")
			if err == io.EOF || choice == "0" {
				return f.save()
			}
			if err != nil {
				return err
			}
			if choice != "1" {
				continue
			}
			choices := []setupChoice{}
			for i, stage := range f.stages {
				choices = append(choices, setupChoice{value: strconv.Itoa(i), label: stage.Label})
			}
			value, err := f.ui.choose("Review stage", "", choices)
			if err != nil {
				return err
			}
			f.state.Stage, _ = strconv.Atoi(value)
			if err := f.save(); err != nil {
				return err
			}
			continue
		}
		stage := f.stages[f.state.Stage]
		decisionState := ""
		if stage.ID == "decision" {
			var err error
			decisionState, err = f.decisionRequirement()
			if err != nil {
				fmt.Fprintf(f.ui.output, "Waiting: %v\n", err)
			}
		}
		fmt.Fprintf(f.ui.output, "\nRELAY | %s | %s\n------------------------------------------------------------\n%s (%d/%d)\n", strings.ToUpper(f.state.Role), f.state.Name, stage.Label, f.state.Stage+1, len(f.stages))
		f.showCurrentPhase()
		for n, task := range stage.Tasks {
			if decisionState == "not-applicable" {
				break
			}
			last := f.last(task)
			if last != nil && (last.Status == "running" || last.Status == "failed") {
				fmt.Fprintf(f.ui.output, "Needs attention: %d — %s. Review the retained attempt before retrying.\n", n+1, task.Label)
				break
			}
			if !task.Optional && (last == nil || (last.Status != "succeeded" && last.Status != "reported")) {
				fmt.Fprintf(f.ui.output, "Suggested next step: %d — %s. This is local progress guidance, not ceremony authorization.\n", n+1, task.Label)
				break
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
					status = "Waiting — unresolved investigation"
				}
				if a.FinishedAt != "" {
					status += " (" + a.FinishedAt + ")"
				}
				if err := f.checkAttemptEvidence(a); err != nil {
					status = "Needs attention — " + err.Error()
				}
			}
			label := task.Label
			status = f.taskProgress(task)
			reason := "Required by the role's operating procedure; commands enforce cryptographic checks"
			if task.Optional {
				reason = "Conditional helper; required evidence and production gates still apply"
			}
			if stage.ID == "decision" {
				reason = "Required for production authorization; cannot be skipped"
			}
			fmt.Fprintf(f.ui.output, "\n%d) %s\n   %s\n   %s\n", n+1, label, reason, status)
		}
		if decisionState == "not-applicable" {
			fmt.Fprintln(f.ui.output, "Production decision actions hidden: not applicable to this authenticated rehearsal.")
		}
		nextLabel := "Review role completion and retention"
		if f.state.Stage+1 < len(f.stages) {
			nextLabel = "Open " + f.stages[f.state.Stage+1].Label
		}
		fmt.Fprintf(f.ui.output, "\n%d) %s\n%d) Review/recover earlier stage\n0) Save and exit\n", len(stage.Tasks)+1, nextLabel, len(stage.Tasks)+2)
		choice, err := f.ui.ask("Choose", "0")
		if err == io.EOF {
			return f.save()
		}
		if err != nil {
			return err
		}
		n, err := strconv.Atoi(choice)
		if err != nil || n < 0 || n > len(stage.Tasks)+2 {
			fmt.Fprintln(f.ui.output, "Choose a displayed number.")
			continue
		}
		if n == 0 {
			return f.save()
		}
		switch n {
		case len(stage.Tasks) + 1:
			err = f.advance()
		case len(stage.Tasks) + 2:
			choices := []setupChoice{}
			for i := 0; i <= f.state.Stage; i++ {
				choices = append(choices, setupChoice{value: strconv.Itoa(i), label: f.stages[i].Label})
			}
			var value string
			value, err = f.ui.choose("Review stage", strconv.Itoa(f.state.Stage), choices)
			if err == nil {
				f.state.Stage, _ = strconv.Atoi(value)
				err = f.save()
			}
		default:
			err = f.execute(stage.Tasks[n-1])
		}
		if err != nil {
			fmt.Fprintf(f.ui.output, "Paused: %v\nFiles and progress retained. Do not bypass verification.\n", err)
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
	f := roleFlow{state: roleFlowState{Schema: roleFlowSchema, Name: p.Name, Role: p.Role, CatalogDigest: catalogDigest, Profile: p, Values: map[string]string{}}, stages: stages, path: statePath, ui: coordinatorWizard{input: bufio.NewReader(os.Stdin), output: os.Stdout}}
	if p.Role == "coordinator" {
		if st, err := os.Lstat(filepath.Join(p.Trust, "setup-coordinator.hex")); err == nil && st.Mode().IsRegular() {
			f.state.Values["shared/coordinator-public-key-file"] = "/trust/setup-coordinator.hex"
		}
	}
	if _, err := os.Lstat(statePath); err == nil {
		if err := setupReadJSON(statePath, &f.state); err != nil {
			return err
		}
		if f.state.Schema != roleFlowSchema || f.state.CatalogDigest != catalogDigest || f.state.Name != p.Name || f.state.Role != p.Role || !reflect.DeepEqual(f.state.Profile, p) || f.state.Stage < 0 || f.state.Stage > len(stages) || f.state.Values == nil {
			return errors.New("workflow does not match saved role settings")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
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
				return fmt.Errorf("prepare the offline signing image in onboarding first: %w", err)
			}
			if offline.Work != p.Work || offline.Trust != p.Trust || offline.Keys == "" || offline.Credentials != "" || offline.ReleaseCommit != p.ReleaseCommit || len(offline.Command) != 0 {
				return errors.New("offline signing profile does not match this role's public folders and release")
			}
			digest, err := f.reviewOfflineRecord(command)
			if err != nil {
				return err
			}
			command = append(append([]string(nil), command...), "--reviewed-sha256", digest)
			open = []string{"ceremony", "open", alias, "--role", "decision-signer", "--settings-root", root}
		}
		if p.Role == "participant" {
			configPath := ""
			participantArgs := []string{command[0]}
			for n := 1; n < len(command); n += 2 {
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
