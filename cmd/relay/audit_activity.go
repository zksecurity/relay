package main

// Activity is a sanitized local observation, not signed ceremony evidence.
import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const auditActivityLimit int64 = 64 << 20
const auditActivityFile = "activity.jsonl"

type auditActivityRecord struct {
	Event    diagnosticEvent `json:"event"`
	Previous string          `json:"previous"`
	Hash     string          `json:"hash"`
}

func auditRecordHash(r auditActivityRecord) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func readAuditRecords(root string) ([]auditActivityRecord, bool, error) {
	path := filepath.Join(root, auditActivityFile)
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > auditActivityLimit {
		return nil, false, errors.New("activity log must be a bounded private regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	actual, err := f.Stat()
	if err != nil || !os.SameFile(st, actual) {
		return nil, false, errors.New("activity log changed while opening")
	}
	raw, err := io.ReadAll(io.LimitReader(f, auditActivityLimit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(raw)) > auditActivityLimit {
		return nil, false, errors.New("activity log limit exceeded")
	}
	partial := len(raw) > 0 && raw[len(raw)-1] != '\n'
	lines := bytes.Split(raw, []byte{'\n'})
	records := []auditActivityRecord{}
	previous := ""
	for _, line := range lines[:len(lines)-1] {
		if len(line) == 0 || len(line) > 4096 {
			return nil, false, errors.New("invalid activity record")
		}
		var r auditActivityRecord
		d := json.NewDecoder(bytes.NewReader(line))
		d.DisallowUnknownFields()
		if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
			return nil, false, errors.New("invalid activity record")
		}
		canonical, _ := json.Marshal(r)
		if !bytes.Equal(canonical, line) || r.Event != cleanDiagnosticEvent(r.Event) || r.Event.Sequence != uint64(len(records)+1) || r.Previous != previous || r.Hash != auditRecordHash(r) {
			return nil, false, errors.New("activity record integrity check failed")
		}
		previous = r.Hash
		records = append(records, r)
	}
	return records, partial, nil
}
func readAuditActivity(work string) ([]diagnosticEvent, []string, error) {
	gaps := []string{"local-observations-not-authenticated", "activity-outside-instrumented-relay-actions-not-recorded", "history-before-recording-not-recoverable"}
	root, err := diagnosticRoot(work, false)
	if errors.Is(err, os.ErrNotExist) {
		return []diagnosticEvent{}, append(gaps, "activity-log-missing"), nil
	}
	if err != nil {
		return nil, nil, err
	}
	lock, err := acquireParticipantRunLock("", root)
	if err != nil {
		return nil, nil, err
	}
	defer lock.release()
	records, partial, err := readAuditRecords(root)
	if err != nil {
		return nil, nil, err
	}
	events := []diagnosticEvent{}
	pending := map[string]bool{}
	uncorrelated := false
	for _, r := range records {
		e := r.Event
		events = append(events, e)
		if e.OperationID == "" {
			uncorrelated = true
		}
		if e.OperationID != "" {
			if e.Outcome == "started" {
				pending[e.OperationID] = true
			} else {
				delete(pending, e.OperationID)
			}
		}
	}
	if uncorrelated {
		gaps = append(gaps, "diagnostic-observations-without-operation-correlation")
	}
	if len(records) == 0 {
		gaps = append(gaps, "activity-log-missing")
	}
	if partial {
		gaps = append(gaps, "partial-final-record")
	}
	if len(pending) > 0 {
		gaps = append(gaps, "actions-without-recorded-completion")
	}
	return events, gaps, nil
}
func appendAuditActivity(c diagnosticContext, outcome string, cause error, operation string) error {
	return appendAuditActivityAt(c, outcome, cause, operation, time.Now())
}

func appendAuditActivityAt(c diagnosticContext, outcome string, cause error, operation string, when time.Time) error {
	if c.Work == "" {
		return nil
	}
	root, err := diagnosticRoot(c.Work, true)
	if err != nil {
		return err
	}
	lock, err := acquireParticipantRunLock("", root)
	if err != nil {
		return err
	}
	defer lock.release()
	records, partial, err := readAuditRecords(root)
	if err != nil {
		return err
	}
	if partial {
		return errors.New("activity log has an incomplete final record; preserve it for review")
	}
	previous := ""
	if len(records) > 0 {
		previous = records[len(records)-1].Hash
	}
	code, exit := diagnosticError(cause)
	e := cleanDiagnosticEvent(diagnosticEvent{Time: when.UTC().Format(time.RFC3339Nano), Release: c.Release, Role: c.Role, Stage: c.Stage, Action: c.Action, Outcome: outcome, ErrorCode: code, ExitCode: exit, Sequence: uint64(len(records) + 1), OperationID: operation})
	r := auditActivityRecord{Event: e, Previous: previous}
	r.Hash = auditRecordHash(r)
	raw, _ := json.Marshal(r)
	raw = append(raw, '\n')
	path := filepath.Join(root, auditActivityFile)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	current, statErr := os.Lstat(path)
	if err != nil || statErr != nil || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return errors.New("activity file changed while opening")
	}
	// Reserve space for a completion when admitting a new operation.
	reserve := int64(0)
	if outcome == "started" {
		reserve = 4096
	}
	if opened.Size()+int64(len(raw))+reserve > auditActivityLimit {
		return errors.New("activity retention limit reached; no records were discarded")
	}
	if _, err = f.Write(raw); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func beginAuditActivity(c diagnosticContext) (func(error, io.Writer), error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	operation := hex.EncodeToString(id[:])
	if err := appendAuditActivity(c, "started", nil, operation); err != nil {
		return nil, errors.New("activity recording unavailable; action was not started")
	}
	return func(cause error, out io.Writer) {
		outcome := "succeeded"
		if cause != nil {
			outcome = "failed"
		}
		if err := appendAuditActivity(c, outcome, cause, operation); err != nil && out != nil {
			fmt.Fprintln(out, "Activity completion could not be recorded. The action result is unchanged; inspect recovery state before taking another action.")
		}
	}, nil
}
