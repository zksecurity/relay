package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const auditReportSchema = "relay-activity-report-v1"
const auditReadLimit = 32 << 20

type auditReport struct {
	Schema           string             `json:"schema"`
	CeremonyID       string             `json:"ceremony_id"`
	DefinitionSHA256 string             `json:"definition_sha256"`
	Sources          []auditSource      `json:"sources"`
	Coverage         []string           `json:"coverage"`
	Conflicts        []string           `json:"conflicts,omitempty"`
	Verification     *auditVerification `json:"verification,omitempty"`
}
type auditSource struct {
	ID             string             `json:"id"`
	ReportSHA256   string             `json:"report_sha256,omitempty"`
	ImportLineage  []string           `json:"import_lineage,omitempty"`
	Role           string             `json:"role"`
	Observations   []auditObservation `json:"observations"`
	Events         []diagnosticEvent  `json:"events"`
	ExporterClaims *auditVerification `json:"exporter_claims,omitempty"`
	Gaps           []string           `json:"gaps"`
}
type auditObservation struct {
	ID       string `json:"id"`
	Action   string `json:"action"`
	Status   string `json:"status"`
	Prepared string `json:"prepared"`
	Started  string `json:"started,omitempty"`
	Returned string `json:"returned,omitempty"`
	Resolved string `json:"resolved,omitempty"`
}

func auditHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func auditDigest(s string) (string, error) {
	s = strings.TrimPrefix(s, "sha256:")
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return "", errors.New("audit identity must be a canonical SHA256 digest")
	}
	return s, nil
}
func auditRealPath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return errors.New("audit path must be absolute and clean")
	}
	actual, e := filepath.EvalSymlinks(p)
	if e != nil {
		return errors.New("audit path unavailable")
	}
	if actual != p {
		return errors.New("audit paths must not contain symlinks")
	}
	return nil
}
func auditReadJSON(p string, v any) ([]byte, error) {
	if e := auditRealPath(p); e != nil {
		return nil, e
	}
	st, e := os.Lstat(p)
	if e != nil || !st.Mode().IsRegular() || st.Size() > auditReadLimit {
		return nil, errors.New("audit input must be a bounded regular file")
	}
	f, e := os.Open(p)
	if e != nil {
		return nil, errors.New("audit input unavailable")
	}
	defer f.Close()
	now, e := f.Stat()
	if e != nil || !os.SameFile(st, now) {
		return nil, errors.New("audit input changed")
	}
	raw, e := io.ReadAll(io.LimitReader(f, auditReadLimit+1))
	if e != nil || len(raw) > auditReadLimit {
		return nil, errors.New("audit input exceeds limit")
	}
	if rejectCommitJournalDuplicateFields(raw) != nil {
		return nil, errors.New("audit input has duplicate fields")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("audit input is invalid")
	}
	return raw, nil
}
func auditTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339Nano)
}
func auditOptionalTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return auditTime(*t)
}
func auditAction(s string) string {
	switch s {
	case "download-outbound", "upload-receipt", "upload-candidate", "contribute", "attest-erasure", "sign-receipt", "sign-return", "download-receipt", "download-candidate", "issue-grant", "sign-return-receipt", "commit-outbound", "commit-receipt", "commit-candidate":
		return s
	}
	return "unknown"
}
func auditStatus(s string) string {
	switch s {
	case "prepared", "running", "returned-needs-verification", "reconciled", "abandoned", "failed-no-effects":
		return s
	}
	return "unknown"
}
func auditRole(s string) string {
	switch s {
	case "coordinator", "participant", "release-signer", "observer", "witness", "auditor", "mirror":
		return s
	}
	return "unknown"
}
func auditCoverage() []string {
	return []string{"Local observations are unauthenticated and do not establish protocol acceptance.", "Partial coverage: activity outside Relay, before recording, or removed locally is unavailable.", "No global freshness or mathematical replay is established by this report.", "Public payloads are not bundled; this is not a historical replay archive.", "Absent role exports do not establish inactivity; expected role completeness is not checked.", "Host clocks cannot establish cross-host causal order."}
}
func buildAuditExport(work string) (auditReport, error) {
	var report auditReport
	if e := auditRealPath(work); e != nil {
		return report, e
	}
	lock, e := acquireParticipantRunLock("", work)
	if e != nil {
		return report, errors.New("audit workspace is busy or unavailable")
	}
	defer lock.release()
	var state workflowV4State
	if _, e = auditReadJSON(filepath.Join(work, "workflow-v4", "state.json"), &state); e != nil {
		return report, e
	}
	if state.Schema != workflowV4JournalSchema || state.Marker.Schema != workflowV4MarkerSchema || len(state.Operations) > 8192 || state.Marker.WorkspaceID == "" {
		return report, errors.New("unsupported audit workspace state")
	}
	ceremony, e := auditDigest(state.Marker.Binding.CeremonyID)
	if e != nil {
		return report, e
	}
	definition, e := auditDigest(state.Marker.Binding.Definition.Record.Digest.SHA256)
	if e != nil {
		return report, e
	}
	source := auditSource{ID: auditHash([]byte(state.Marker.WorkspaceID)), Role: auditRole(state.Marker.Binding.Role)}
	for _, op := range state.Operations {
		source.Observations = append(source.Observations, auditObservation{ID: auditHash([]byte(op.Plan.ID)), Action: auditAction(op.Plan.Kind), Status: auditStatus(op.Status), Prepared: auditTime(op.Prepared), Started: auditOptionalTime(op.Started), Returned: auditOptionalTime(op.Returned), Resolved: auditOptionalTime(op.Resolved)})
	}
	coverage := auditCoverage()
	root := filepath.Join(work, diagnosticDirectory)
	if _, e = os.Lstat(root); e == nil {
		if e = auditRealPath(root); e != nil {
			return report, e
		}
		diagnosticLock, lockErr := acquireParticipantRunLock("", root)
		if lockErr != nil {
			return report, errors.New("audit diagnostics are busy or unavailable")
		}
		events, err := readDiagnosticEvents(root)
		_ = diagnosticLock.release()
		if err != nil {
			return report, errors.New("audit diagnostics invalid")
		}
		source.Events = append(source.Events, events...)
		if len(events) == diagnosticLimit {
			source.Gaps = append(source.Gaps, "legacy-diagnostics-at-retention-limit")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return report, errors.New("audit diagnostics unavailable")
	}
	events, gaps, e := readAuditActivity(work)
	if e != nil {
		return report, e
	}
	// Durable observations retain sequence and operation correlation. Remove only
	// duplicate copies from the bounded legacy stream, preserving durable repeats.
	counts := map[string]int{}
	for _, event := range events {
		counts[auditEventKey(event)]++
	}
	legacy := source.Events
	source.Events = nil
	for _, event := range legacy {
		key := auditEventKey(event)
		if counts[key] > 0 {
			counts[key]--
			continue
		}
		source.Events = append(source.Events, event)
	}
	for _, event := range events {
		source.Events = append(source.Events, cleanDiagnosticEvent(event))
	}
	source.Gaps = append(source.Gaps, gaps...)
	report = auditReport{Schema: auditReportSchema, CeremonyID: ceremony, DefinitionSHA256: definition, Sources: []auditSource{source}, Coverage: coverage}
	return report, nil
}
func sanitizeAuditReport(r auditReport) (auditReport, error) {
	if r.Schema != auditReportSchema || len(r.Sources) == 0 || len(r.Sources) > 64 {
		return auditReport{}, errors.New("invalid audit report schema or source count")
	}
	var e error
	if r.CeremonyID, e = auditDigest(r.CeremonyID); e != nil {
		return auditReport{}, e
	}
	if r.DefinitionSHA256, e = auditDigest(r.DefinitionSHA256); e != nil {
		return auditReport{}, e
	}
	r.Coverage = auditCoverage()
	r.Conflicts = nil
	for i := range r.Sources {
		s := &r.Sources[i]
		if s.ID, e = auditDigest(s.ID); e != nil {
			return auditReport{}, e
		}
		if s.ReportSHA256 != "" {
			if s.ReportSHA256, e = auditDigest(s.ReportSHA256); e != nil {
				return auditReport{}, e
			}
		}
		if len(s.ImportLineage) > 64 {
			return auditReport{}, errors.New("audit import lineage exceeds limit")
		}
		for j := range s.ImportLineage {
			if s.ImportLineage[j], e = auditDigest(s.ImportLineage[j]); e != nil {
				return auditReport{}, e
			}
		}
		s.Role = auditRole(s.Role)
		if len(s.Observations) > 8192 || len(s.Events) > 100000 {
			return auditReport{}, errors.New("audit source exceeds event limit")
		}
		for j := range s.Observations {
			o := &s.Observations[j]
			if o.ID, e = auditDigest(o.ID); e != nil {
				return auditReport{}, e
			}
			o.Action = auditAction(o.Action)
			o.Status = auditStatus(o.Status)
			for _, p := range []*string{&o.Prepared, &o.Started, &o.Returned, &o.Resolved} {
				if *p == "" {
					continue
				}
				t, err := time.Parse(time.RFC3339Nano, *p)
				if err != nil {
					*p = "unknown"
				} else {
					*p = auditTime(t)
				}
			}
		}
		for j := range s.Events {
			s.Events[j] = cleanDiagnosticEvent(s.Events[j])
		}
		s.ExporterClaims = auditExporterClaim(s.ExporterClaims)
		s.Gaps = cleanAuditGaps(s.Gaps)
	}
	return r, nil
}
func combineAuditExports(inputs []string) (auditReport, error) {
	var out auditReport
	if len(inputs) == 0 || len(inputs) > 64 {
		return out, errors.New("combine requires 1 to 64 exports")
	}
	seen := map[string]bool{}
	sourceHashes := map[string]string{}
	for _, input := range inputs {
		var r auditReport
		raw, e := auditReadJSON(filepath.Join(input, "report.json"), &r)
		if e != nil {
			return out, e
		}
		hash := auditHash(raw)
		if seen[hash] {
			continue
		}
		seen[hash] = true
		r, e = sanitizeAuditReport(r)
		if e != nil {
			return out, e
		}
		if out.Schema == "" {
			out = auditReport{Schema: auditReportSchema, CeremonyID: r.CeremonyID, DefinitionSHA256: r.DefinitionSHA256, Coverage: auditCoverage()}
		} else if out.CeremonyID != r.CeremonyID || out.DefinitionSHA256 != r.DefinitionSHA256 {
			return auditReport{}, errors.New("cannot combine different ceremony or definition identities")
		}
		for _, s := range r.Sources {
			if old, ok := sourceHashes[s.ID]; ok && old != hash {
				out.Conflicts = append(out.Conflicts, "Different snapshots supplied for source "+s.ID)
			}
			sourceHashes[s.ID] = hash
			if s.ReportSHA256 != "" {
				s.ImportLineage = append(s.ImportLineage, s.ReportSHA256)
				if len(s.ImportLineage) > 64 {
					return auditReport{}, errors.New("audit import lineage exceeds limit")
				}
			}
			s.ReportSHA256 = hash
			if r.Verification != nil {
				s.ExporterClaims = auditExporterClaim(r.Verification)
			}
			out.Sources = append(out.Sources, s)
			if len(out.Sources) > 64 {
				return auditReport{}, errors.New("combined source count exceeds limit")
			}
		}
	}
	sort.Strings(out.Conflicts)
	out.Coverage = append(out.Coverage, "Imported verification results are exporter claims, not independently authenticated by combination.")
	return out, nil
}
func writeAuditReport(out string, report auditReport) error {
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return errors.New("audit output must be absolute and clean")
	}
	if e := auditRealPath(filepath.Dir(out)); e != nil {
		return e
	}
	// Project observations again even for internally produced reports.
	clean, e := sanitizeAuditReport(report)
	if e != nil {
		return e
	}
	clean.Verification = cleanAuditVerification(report.Verification)
	for _, conflict := range report.Conflicts {
		const prefix = "Different snapshots supplied for source "
		if strings.HasPrefix(conflict, prefix) {
			digest, err := auditDigest(strings.TrimPrefix(conflict, prefix))
			if err == nil && conflict == prefix+digest {
				clean.Conflicts = append(clean.Conflicts, conflict)
			}
		}
	}
	clean.Coverage = append(clean.Coverage, "Coverage is partial, including legacy bounded diagnostics and any recording interruptions.")
	raw, e := json.MarshalIndent(clean, "", "  ")
	if e != nil {
		return errors.New("cannot encode audit report")
	}
	if len(raw) > auditReadLimit {
		return errors.New("audit report exceeds limit")
	}
	var md strings.Builder
	fmt.Fprintf(&md, "# Ceremony activity report\n\nCeremony: `%s`\n\nDefinition SHA256: `%s`\n\n", clean.CeremonyID, clean.DefinitionSHA256)
	if v := clean.Verification; v != nil {
		fmt.Fprintf(&md, "## Verification performed during export\n\nStatus: %s. Depth: %s. Checkpoint sequence: %d. Accepted contributions: phase 1 %d, phase 2 %d.\n\nCheckpoint SHA256: `%s`\n\nCoordinator key SHA256: `%s`\n\nVerifier SHA256: `%s`\n\n", v.Status, v.Depth, v.Sequence, v.Phase1Accepted, v.Phase2Accepted, v.CheckpointSHA256, v.CoordinatorKeySHA256, v.VerifierSHA256)
		for _, progress := range v.Progress {
			fmt.Fprintf(&md, "- %s\n", progress)
		}
		md.WriteString("\nThis report is unsigned; verification results are self-described. No mathematical replay or global freshness is established.\n\n")
	}
	for _, c := range clean.Coverage {
		fmt.Fprintf(&md, "- %s\n", c)
	}
	for _, c := range clean.Conflicts {
		fmt.Fprintf(&md, "\nConflict: %s\n", c)
	}
	for _, s := range clean.Sources {
		fmt.Fprintf(&md, "\n## %s — source `%s`\n\nUnauthenticated local observations: %d journal operations, %d recorded events.\n\n", s.Role, s.ID, len(s.Observations), len(s.Events))
		for _, gap := range s.Gaps {
			fmt.Fprintf(&md, "- Coverage: %s\n", gap)
		}
		if s.ExporterClaims != nil {
			fmt.Fprintf(&md, "Verification status: exporter-reported. Checkpoint SHA256: `%s`. Not independently authenticated.\n\n", s.ExporterClaims.CheckpointSHA256)
		}
		for _, o := range s.Observations {
			fmt.Fprintf(&md, "- `%s`: %s — %s (prepared %s)\n", o.ID, o.Action, o.Status, o.Prepared)
		}
		for _, ev := range s.Events {
			fmt.Fprintf(&md, "- %s: %s / %s — %s (%s)\n", ev.Time, ev.Stage, ev.Action, ev.Outcome, ev.ErrorCode)
		}
	}
	if e = os.Mkdir(out, 0700); e != nil {
		return errors.New("audit output must be a fresh directory")
	}
	if e = os.WriteFile(filepath.Join(out, "report.json"), append(raw, '\n'), 0600); e != nil {
		return errors.New("audit JSON write failed; incomplete output retained")
	}
	if e = os.WriteFile(filepath.Join(out, "report.md"), []byte(md.String()), 0600); e != nil {
		return errors.New("audit Markdown write failed; incomplete output retained")
	}
	return nil
}

func auditEventKey(e diagnosticEvent) string {
	e = cleanDiagnosticEvent(e)
	e.Sequence = 0
	e.OperationID = ""
	raw, _ := json.Marshal(e)
	return string(raw)
}
func cleanAuditGaps(gaps []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, g := range gaps {
		switch g {
		case "local-observations-not-authenticated", "activity-outside-instrumented-relay-actions-not-recorded", "history-before-recording-not-recoverable", "activity-log-missing", "diagnostic-observations-without-operation-correlation", "partial-final-record", "actions-without-recorded-completion", "legacy-diagnostics-at-retention-limit":
			if !seen[g] {
				out = append(out, g)
				seen[g] = true
			}
		}
	}
	return out
}
