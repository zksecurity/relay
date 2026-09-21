package upgrade

// Qualification is a build-time operation, not a launcher verification bypass.
// The reviewed integration test binary must exercise the actual supplied assets.
// Missing tests, skipped branches and changed assets never produce a report.
import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

var qualificationTests = map[string]string{
	"full-journey":             "TestUpgradeQualificationFullJourney",
	"mixed-versions":           "TestUpgradeQualificationMixedVersions",
	"retained-work":            "TestUpgradeQualificationRetainedWork",
	"activation-crashes":       "TestUpgradeQualificationActivationCrashes",
	"execution-exclusion":      "TestUpgradeQualificationExecutionExclusion",
	"predecessor-reentry":      "TestUpgradeQualificationPredecessorReentry",
	"published-reconstruction": "TestUpgradeQualificationPublishedReconstruction",
}

// Paths are private runner input. They must never be included in public reports.
type QualificationRequest struct {
	Declaration  DeclarationV2     `json:"declaration"`
	Candidate    string            `json:"candidate"`
	Predecessors map[string]string `json:"predecessors"`
	TestBinary   string            `json:"test_binary"`
}

func qualificationFileHash(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("qualification needs absolute clean asset paths")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		return "", errors.New("qualification asset must be a regular executable, not a symlink")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", errors.New("qualification asset changed while opening")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, after) || info.Size() != after.Size() || info.ModTime() != after.ModTime() {
		return "", errors.New("qualification asset changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Require the named test to run and pass, as well as the test process/package.
// In particular `go test` exits successfully when the selected test is absent.
func VerifyQualificationTestEvents(r io.Reader, name string) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	states := map[string]string{}
	finished := false
	for scanner.Scan() {
		var e struct{ Action, Test, Package string }
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return errors.New("invalid qualification test event")
		}
		if finished {
			return errors.New("events after qualification process completion")
		}
		if e.Package != "upgrade-qualification" {
			return errors.New("unexpected qualification package")
		}
		switch e.Action {
		case "start", "output", "run", "pass", "pause", "cont", "fail", "skip":
		default:
			return errors.New("unknown qualification event")
		}
		if e.Action == "fail" || e.Action == "skip" {
			return errors.New("qualification scenario failed or skipped")
		}
		if e.Test != "" && e.Test != name && !strings.HasPrefix(e.Test, name+"/") {
			return errors.New("unexpected qualification scenario")
		}
		if e.Test != "" {
			switch e.Action {
			case "run":
				if states[e.Test] != "" {
					return errors.New("duplicate qualification test")
				}
				states[e.Test] = "running"
			case "pass":
				if states[e.Test] != "running" {
					return errors.New("qualification pass without execution")
				}
				states[e.Test] = "passed"
			case "pause":
				if states[e.Test] != "running" {
					return errors.New("invalid qualification pause")
				}
				states[e.Test] = "paused"
			case "cont":
				if states[e.Test] != "paused" {
					return errors.New("invalid qualification continuation")
				}
				states[e.Test] = "running"
			}
		}
		if e.Test == "" && e.Action == "pass" {
			if states[name] != "passed" {
				return errors.New("required qualification scenario did not execute")
			}
			for _, state := range states {
				if state != "passed" {
					return errors.New("unfinished qualification subtest")
				}
			}
			finished = true
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if states[name] != "passed" || !finished {
		return errors.New("incomplete qualification test execution")
	}
	return nil
}

// RunQualification executes all required scenarios, then rehashes every input.
// The caller must use a deadline. Reports are returned only on complete success.
// The test executable receives the exact request via a protected temporary file;
// fixture creation and test-only activation remain entirely outside production CLI.
func RunQualification(ctx context.Context, request QualificationRequest) (QualificationV2, error) {
	var zero QualificationV2
	d := request.Declaration
	// The eventual report hash cannot be known before execution.
	d.QualificationSHA256 = "sha256:" + strings.Repeat("0", 64)
	if err := d.Validate(); err != nil {
		return zero, err
	}
	if d.Host != runtime.GOOS+"/"+runtime.GOARCH {
		return zero, errors.New("qualification must run on the declared host")
	}
	if _, ok := ctx.Deadline(); !ok {
		return zero, errors.New("qualification requires an execution deadline")
	}
	if len(request.Predecessors) != len(d.SafePredecessors) {
		return zero, errors.New("missing predecessor binaries")
	}
	hashes := map[string]string{}
	paths := []string{request.Candidate, request.TestBinary}
	for _, commit := range d.SafePredecessors {
		paths = append(paths, request.Predecessors[commit])
	}
	for _, path := range paths {
		h, err := qualificationFileHash(path)
		if err != nil {
			return zero, err
		}
		hashes[path] = h
	}
	q := QualificationV2{Schema: "relay-upgrade-qualification/v2", OriginalRelease: d.OriginalRelease, SourceApp: d.SourceApp, TargetApp: d.TargetApp, Role: d.Role, Host: d.Host, Platform: d.Platform, LauncherSHA256: hashes[request.Candidate], OnlineImage: d.OnlineImage, ProofToolSHA256: d.ProofToolSHA256, OriginalImage: d.OriginalImage, SigningImage: d.SigningImage, Predecessors: map[string]string{}}
	for commit, path := range request.Predecessors {
		q.Predecessors[commit] = hashes[path]
	}
	tmp, err := os.MkdirTemp("", "relay-upgrade-qualification-")
	if err != nil {
		return zero, err
	}
	defer os.RemoveAll(tmp)
	raw, err := json.Marshal(request)
	if err != nil {
		return zero, err
	}
	input := filepath.Join(tmp, "request.json")
	if err := os.WriteFile(input, raw, 0600); err != nil {
		return zero, err
	}
	for _, check := range QualificationChecks {
		name := qualificationTests[check]
		scenarioContext, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(scenarioContext, "go", "tool", "test2json", "-p", "upgrade-qualification", request.TestBinary, "-test.v=test2json", "-test.run=^"+name+"$", "-test.count=1", "-test.timeout=30m")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
		cmd.WaitDelay = 5 * time.Second
		cmd.Env = append(os.Environ(), "RELAY_UPGRADE_QUALIFICATION_REQUEST="+input)
		// Keep private test output out of public errors and release assets.
		log, err := os.CreateTemp(tmp, "events-")
		if err != nil {
			cancel()
			return zero, err
		}
		cmd.Stdout, cmd.Stderr = &qualificationLog{writer: log, remaining: 16 << 20, cancel: cancel}, io.Discard
		err = cmd.Run()
		cancel()
		// test2json is a parent of the real scenario process. Do not leave that
		// process running after timeout/cancellation of its parent.
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		if err == nil {
			_, err = log.Seek(0, 0)
		}
		if err == nil {
			err = VerifyQualificationTestEvents(log, name)
		}
		log.Close()
		if err != nil {
			return zero, fmt.Errorf("qualification %s did not pass: %w", check, err)
		}
		q.Passed = append(q.Passed, check)
	}
	for path, expected := range hashes {
		h, err := qualificationFileHash(path)
		if err != nil || h != expected {
			return zero, errors.New("qualification input changed during execution")
		}
	}
	raw, err = json.Marshal(q)
	if err != nil {
		return zero, err
	}
	return VerifyQualification(raw, d)
}

type qualificationLog struct {
	writer    io.Writer
	remaining int
	cancel    context.CancelFunc
}

func (w *qualificationLog) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		if w.cancel != nil {
			w.cancel()
		}
		return 0, errors.New("qualification output exceeds limit")
	}
	n, err := w.writer.Write(p)
	w.remaining -= n
	return n, err
}
