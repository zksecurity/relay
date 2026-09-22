package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestQualificationLogOverflowCancelsExecution(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var buffer bytes.Buffer
	w := qualificationLog{writer: &buffer, remaining: 4, cancel: cancel}
	if _, err := w.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("5")); err == nil {
		t.Fatal("output limit ignored")
	}
	if ctx.Err() == nil || buffer.String() != "1234" {
		t.Fatal("overflow did not cancel without growing output")
	}
}

func TestQualificationRequiresExecutedUnskippedScenario(t *testing.T) {
	name := "TestUpgradeQualificationFullJourney"
	event := func(action, test string) string {
		raw, _ := json.Marshal(map[string]string{"Action": action, "Test": test, "Package": "upgrade-qualification"})
		return string(raw) + "\n"
	}
	good := event("run", name) + event("pass", name) + event("pass", "")
	if err := VerifyQualificationTestEvents(strings.NewReader(good), name); err != nil {
		t.Fatal(err)
	}
	for label, events := range map[string]string{
		"no tests":           event("pass", ""),
		"skipped test":       event("run", name) + event("skip", name) + event("pass", ""),
		"skipped subtest":    event("run", name) + event("skip", name+"/live") + event("pass", name) + event("pass", ""),
		"failed test":        event("run", name) + event("fail", name),
		"truncated":          event("run", name) + event("pass", name),
		"another test":       event("run", "TestOther") + event("pass", "TestOther") + event("pass", ""),
		"reused":             good + good,
		"no execution":       event("pass", name) + event("pass", ""),
		"unfinished subtest": event("run", name) + event("run", name+"/child") + event("pass", name) + event("pass", ""),
		"unknown action":     event("magic", name) + good,
		"wrong package":      strings.ReplaceAll(good, "upgrade-qualification", "another-package"),
		"raw text":           "PASS\n",
	} {
		t.Run(label, func(t *testing.T) {
			if VerifyQualificationTestEvents(strings.NewReader(events), name) == nil {
				t.Fatal("accepted missing/failed execution")
			}
		})
	}
}

func TestQualificationAssetValidation(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "asset")
	if err := os.WriteFile(file, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := qualificationFileHash(file); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", root, link} {
		if _, err := qualificationFileHash(path); err == nil {
			t.Fatal("accepted non-executable or ambiguous path")
		}
	}
}

func TestQualificationRunnerCannotUseUnitTestsAsJourneyEvidence(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	d := fixtureV2()
	d.Host = runtime.GOOS + "/" + runtime.GOARCH
	request := QualificationRequest{Declaration: d, Candidate: exe, TestBinary: exe, Predecessors: map[string]string{d.OriginalRelease: exe}}
	if _, err := RunQualification(context.Background(), request); err == nil {
		t.Fatal("accepted unbounded execution")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// This real test executable contains no full-journey qualification scenario.
	// A zero-exit `no tests to run` result must not create a qualification report.
	for _, schema := range []string{"", OnlineCleanExitQualificationSchema} {
		request.QualificationSchema = schema
		q, err := RunQualification(ctx, request)
		if err == nil || len(q.Passed) != 0 {
			t.Fatal("missing real scenarios created a passing report", schema, q, err)
		}
	}
}
