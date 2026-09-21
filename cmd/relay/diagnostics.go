package main

// Diagnostics are deliberately a projection, never a copy of commands, process
// output, environment, profiles, or ceremony artifacts. Unknown errors get a
// fixed category rather than attempting to redact arbitrary child output.
import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const diagnosticLimit = 100
const diagnosticDirectory = ".relay-diagnostics"

type diagnosticEvent struct {
	Sequence    uint64 `json:"sequence,omitempty"`
	OperationID string `json:"operation_id,omitempty"`
	Time        string `json:"time"`
	Release     string `json:"release"`
	Role        string `json:"role"`
	Stage       string `json:"stage"`
	Action      string `json:"action"`
	Outcome     string `json:"outcome"`
	ErrorCode   string `json:"error_code,omitempty"`
	ExitCode    int    `json:"exit_code,omitempty"`
}

type diagnosticContext struct{ Work, Role, Release, Stage, Action string }

func diagnosticError(err error) (string, int) {
	if err == nil {
		return "", 0
	}
	var exit *exec.ExitError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", 0
	case errors.Is(err, context.Canceled), errors.Is(err, io.EOF), errors.Is(err, errSecretPromptInterrupted):
		return "cancelled", 0
	case errors.Is(err, os.ErrNotExist):
		return "missing-file", 0
	case errors.Is(err, os.ErrPermission):
		return "permission-denied", 0
	case errors.Is(err, os.ErrExist):
		return "output-exists", 0
	case errors.As(err, &exit):
		return "child-exit", exit.ExitCode()
	}
	// Only fixed diagnoses leave the process, never a substring from err.
	message := strings.ToLower(err.Error())
	for _, rule := range []struct{ text, code string }{
		{"an approved immutable image is required", "image-required"},
		{"offline signing profile does not match", "profile-mismatch"},
		{"another participant run is already active", "workspace-busy"},
		{"another relay helper or run is already active", "workspace-busy"},
		{"cancelled", "cancelled"},
		{"signature", "signature-check-failed"},
		{"prerequisite", "prerequisite-missing"},
	} {
		if strings.Contains(message, rule.text) {
			return rule.code, 0
		}
	}
	return "operation-failed", 0
}

func diagnosticRelease(value string) string {
	value = strings.TrimPrefix(value, "role-images-")
	if regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(value) {
		return value
	}
	return "local-or-unknown"
}

// Validate again when exporting: a locally edited event file is not trusted.
func cleanDiagnosticEvent(e diagnosticEvent) diagnosticEvent {
	if t, err := time.Parse(time.RFC3339Nano, e.Time); err == nil {
		e.Time = t.UTC().Format(time.RFC3339Nano)
	} else {
		e.Time = "unknown"
	}
	e.Release = diagnosticRelease(e.Release)
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(e.OperationID) {
		e.OperationID = ""
	}
	stages := roleFlowStages(e.Role)
	if len(stages) == 0 {
		e.Role = "unknown"
	}
	valid := false
	if e.Stage == "workflow-v4" {
		switch e.Action {
		case "enrollment", "participant-action", "coordinator-action", "coordinator-lifecycle", "release-signer-action", "export-public-snapshot", "import-signer-enrollment", "upload-signer-package":
			valid = true
		}
	} else if e.Stage == "launcher" {
		valid = e.Action == "open-guide"
	} else if e.Stage == "setup" {
		n, err := strconv.Atoi(e.Action)
		valid = err == nil && n >= 1 && n <= 17 && e.Action == strconv.Itoa(n)
	} else {
		for _, s := range stages {
			if s.ID == e.Stage {
				for _, task := range s.Tasks {
					if task.ID == e.Action {
						valid = true
					}
				}
			}
		}
	}
	if !valid {
		e.Stage, e.Action = "unknown", "unknown"
	}
	switch e.Outcome {
	case "started", "succeeded", "failed":
	default:
		e.Outcome = "unknown"
	}
	switch e.ErrorCode {
	case "", "timeout", "cancelled", "missing-file", "permission-denied", "output-exists", "child-exit", "image-required", "profile-mismatch", "workspace-busy", "signature-check-failed", "prerequisite-missing", "operation-failed":
	default:
		e.ErrorCode = "operation-failed"
	}
	if e.ExitCode < -1 || e.ExitCode > 255 {
		e.ExitCode = 0
	}
	return e
}

func diagnosticRoot(work string, create bool) (string, error) {
	if !filepath.IsAbs(work) {
		return "", errors.New("diagnostics require an absolute role work folder")
	}
	// Resolve the user-selected work root once; reject links beneath that root.
	work, err := filepath.EvalSymlinks(work)
	if err != nil {
		return "", err
	}
	root := filepath.Join(work, diagnosticDirectory)
	if create {
		if err := ensurePrivateDirectory(root); err != nil {
			return "", err
		}
	}
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("diagnostics folder must be a private directory, not a link")
	}
	return root, nil
}

func readDiagnosticEvents(root string) ([]diagnosticEvent, error) {
	path := filepath.Join(root, "events.json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 128<<10 {
		return nil, errors.New("diagnostic log is not a bounded private regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(info, actual) {
		return nil, errors.New("diagnostic log changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (128<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 128<<10 {
		return nil, errors.New("diagnostic log is too large")
	}
	var events []diagnosticEvent
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&events); err != nil {
		return nil, errors.New("diagnostic log is invalid")
	}
	if decoder.Decode(new(any)) != io.EOF || len(events) > diagnosticLimit {
		return nil, errors.New("diagnostic log is invalid")
	}
	for i := range events {
		events[i] = cleanDiagnosticEvent(events[i])
	}
	return events, nil
}

func recordDiagnostic(c diagnosticContext, outcome string, cause error, output io.Writer) {
	if c.Work == "" {
		return
	} // test-only flows without a role folder
	when := time.Now()
	if err := appendAuditActivityAt(c, outcome, cause, "", when); err != nil && output != nil {
		fmt.Fprintln(output, "Activity log unavailable. Action result is unchanged; this observation may be missing from the audit.")
	}
	if err := appendDiagnosticAt(c, outcome, cause, when); err != nil && output != nil {
		fmt.Fprintln(output, "Diagnostic log unavailable. Ceremony recovery state is separate; the action's result is unchanged.")
	}
}

func appendDiagnostic(c diagnosticContext, outcome string, cause error) error {
	return appendDiagnosticAt(c, outcome, cause, time.Now())
}

func appendDiagnosticAt(c diagnosticContext, outcome string, cause error, when time.Time) error {
	root, err := diagnosticRoot(c.Work, true)
	if err != nil {
		return err
	}
	lock, err := acquireParticipantRunLock(filepath.Join(root, "events.json"), root)
	if err != nil {
		return err
	}
	defer lock.release()
	events, err := readDiagnosticEvents(root)
	if err != nil {
		return err
	}
	code, exit := diagnosticError(cause)
	e := cleanDiagnosticEvent(diagnosticEvent{Time: when.UTC().Format(time.RFC3339Nano), Release: c.Release, Role: c.Role, Stage: c.Stage, Action: c.Action, Outcome: outcome, ErrorCode: code, ExitCode: exit})
	events = append(events, e)
	if len(events) > diagnosticLimit {
		events = events[len(events)-diagnosticLimit:]
	}
	return saveJSONAtomic(filepath.Join(root, "events.json"), events)
}

func diagnosticVersion(command string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Docker --version checks the local client only, never contacts a daemon.
	var out limitedDiagnosticOutput
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.WaitDelay = 500 * time.Millisecond
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "unavailable"
	}
	match := regexp.MustCompile(`\b[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,6})?\b`).FindString(out.String())
	if match == "" {
		return "unavailable"
	}
	return match
}

type limitedDiagnosticOutput struct{ buffer bytes.Buffer }

func (b *limitedDiagnosticOutput) String() string { return b.buffer.String() }

func (b *limitedDiagnosticOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := 4096 - b.buffer.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.buffer.Write(p)
	}
	return n, nil
}

func diagnosticFileStatus(work string) map[string]string {
	result := map[string]string{}
	for label, relative := range map[string]string{"definition": "ceremony/public/ceremony.json", "definition-signature": "ceremony/public/ceremony.sig", "enrollment": "enrollment.json", "enrollment-signature": "enrollment.sig"} {
		status := "present-unverified"
		path := work
		for _, part := range strings.Split(relative, "/") {
			path = filepath.Join(path, part)
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				status = "missing"
				break
			}
			if err != nil {
				status = "unavailable"
				break
			}
			if info.Mode()&os.ModeSymlink != 0 {
				status = "symlink-not-inspected"
				break
			}
			if path == filepath.Join(work, relative) && !info.Mode().IsRegular() {
				status = "not-regular"
			}
		}
		result[label] = status
	}
	return result
}

const diagnosticReadme = `Relay bug report

Contents: report.json only, plus this README.
The report contains a random report ID, UTC times, release commits, role/step
names, operation outcomes, fixed error categories, host OS/CPU and local Docker
client version, and existence checks for four expected public files.

No raw terminal output, command arguments, environment, usernames, host paths,
signing keys, grants, credentials, profiles, or ceremony artifacts are included.
Unknown error details are omitted. File presence is NOT signature verification.
An operation succeeding is NOT proof of contribution acceptance or secret erasure.
The last 100 events are retained; started means the guided action was selected,
not that a child process necessarily launched. Empty events means no log exists.
Events are local diagnostics, not authenticated evidence. Reports are not uploaded.
Unzip and review report.json before attaching this ZIP to a bug report.
Describe what you expected and saw, but do not include secrets.
`

func exportDiagnostics(work, out string) (string, error) {
	if !filepath.IsAbs(out) {
		return "", errors.New("report output must be an absolute fresh ZIP path")
	}
	if !filepath.IsAbs(work) {
		return "", errors.New("provide an absolute role work folder")
	}
	info, err := os.Stat(work)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("role work folder must be a directory")
	}
	root, err := diagnosticRoot(work, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("no readable diagnostics in this role work folder: %w", err)
	}
	events := []diagnosticEvent{}
	if err == nil {
		events, err = readDiagnosticEvents(root)
		if err != nil {
			return "", err
		}
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(random[:])
	osVersion := "unavailable"
	if runtime.GOOS == "darwin" {
		osVersion = diagnosticVersion("sw_vers", "-productVersion")
	} else if runtime.GOOS == "linux" {
		osVersion = diagnosticVersion("uname", "-r")
	}
	report := struct {
		Schema          string            `json:"schema"`
		ID              string            `json:"report_id"`
		Created         string            `json:"created_at"`
		ExporterRelease string            `json:"exporter_release"`
		OS              string            `json:"os"`
		OSVersion       string            `json:"os_version"`
		Arch            string            `json:"architecture"`
		Docker          string            `json:"docker_client_version"`
		Events          []diagnosticEvent `json:"events"`
		Files           map[string]string `json:"expected_public_files"`
	}{"relay-diagnostic-report-v1", id, time.Now().UTC().Format(time.RFC3339Nano), diagnosticRelease(launcherCommit()), runtime.GOOS, osVersion, runtime.GOARCH, diagnosticVersion("docker", "--version"), events, diagnosticFileStatus(work)}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(out)
		}
	}()
	z := zip.NewWriter(f)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"README.txt", []byte(diagnosticReadme)}, {"report.json", raw}} {
		h := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		h.SetMode(0600)
		w, e := z.CreateHeader(h)
		if e != nil {
			return "", e
		}
		if _, e = w.Write(entry.data); e != nil {
			return "", e
		}
	}
	if err = z.Close(); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	ok = true
	return id, nil
}

func runDiagnostics(args []string) error {
	if len(args) == 0 || args[0] != "export" {
		return errors.New("usage: relay diagnostics export --work ROLE_WORK --out FRESH_ZIP")
	}
	flags := flag.NewFlagSet("diagnostics export", flag.ContinueOnError)
	work := flags.String("work", "", "absolute role work folder")
	out := flags.String("out", "", "absolute fresh ZIP path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *work == "" || *out == "" {
		return errors.New("provide --work and --out; no other arguments")
	}
	id, err := exportDiagnostics(*work, *out)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "Report %s saved: %s\nUnzip and review README.txt and report.json before sharing. Nothing was uploaded.\n", id, *out)
	return nil
}

func (w *coordinatorWizard) exportDiagnosticReport(work string) {
	fmt.Fprintln(w.output, "Export includes the last 100 structured events, fixed error categories, runtime versions and public-file presence. No raw output, keys, credentials, paths or artifacts. Nothing is uploaded.")
	path, err := w.ask("Fresh bug-report ZIP", filepath.Join(work, "relay-bug-report-"+time.Now().UTC().Format("20060102T150405Z")+".zip"))
	if err == nil {
		var id string
		id, err = exportDiagnostics(work, path)
		if err == nil {
			fmt.Fprintf(w.output, "Report %s saved: %s\nUnzip and review README.txt and report.json before sharing.\n", id, path)
		}
	}
	if err != nil {
		w.message(toneError, "Report export failed: %v\nCeremony files and progress are unchanged.\n", err)
	}
}
