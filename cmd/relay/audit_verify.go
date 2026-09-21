package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zksecurity/relay/internal/transcript"
)

type auditVerification struct {
	DefinitionSignatureSHA256 string   `json:"definition_signature_sha256,omitempty"`
	CheckpointSignatureSHA256 string   `json:"checkpoint_signature_sha256,omitempty"`
	Status                    string   `json:"status"`
	Depth                     string   `json:"depth"`
	CeremonyID                string   `json:"ceremony_id,omitempty"`
	DefinitionSHA256          string   `json:"definition_sha256,omitempty"`
	CheckpointSHA256          string   `json:"checkpoint_sha256,omitempty"`
	CoordinatorKeySHA256      string   `json:"coordinator_key_sha256,omitempty"`
	VerifierSHA256            string   `json:"verifier_sha256,omitempty"`
	Sequence                  uint64   `json:"sequence"`
	Phase1Accepted            uint64   `json:"phase1_accepted"`
	Phase2Accepted            uint64   `json:"phase2_accepted"`
	Progress                  []string `json:"progress"`
	MathematicsReplayed       bool     `json:"mathematics_replayed"`
	GlobalFreshnessVerified   bool     `json:"global_freshness_verified"`
}

func cleanAuditVerification(v *auditVerification) *auditVerification {
	if v == nil {
		return nil
	}
	out := *v
	switch out.Status {
	case "not-run", "passed", "failed", "exporter-reported":
	default:
		out.Status = "not-run"
	}
	if out.Depth != "checkpoint-structure" {
		out.Depth = "not-run"
	}
	for _, p := range []*string{&out.CeremonyID, &out.DefinitionSHA256, &out.CheckpointSHA256, &out.DefinitionSignatureSHA256, &out.CheckpointSignatureSHA256, &out.CoordinatorKeySHA256, &out.VerifierSHA256} {
		if !strings.HasPrefix(*p, "sha256:") || !sha256HexPattern.MatchString(strings.TrimPrefix(*p, "sha256:")) {
			*p = ""
		}
	}
	out.MathematicsReplayed = false
	out.GlobalFreshnessVerified = false
	out.Progress = []string{}
	for _, p := range v.Progress {
		switch p {
		case "phase1", "phase1-closed", "phase1-beacon", "phase1-sealed", "phase2", "phase2-closed", "phase2-beacon", "final-candidate", "release-review", "final-release", "terminal":
			if len(out.Progress) < 16 {
				out.Progress = append(out.Progress, p)
			}
		}
	}
	if out.Phase1Accepted > 20 {
		out.Phase1Accepted = 0
	}
	if out.Phase2Accepted > 20 {
		out.Phase2Accepted = 0
	}
	return &out
}
func auditExporterClaim(v *auditVerification) *auditVerification {
	out := cleanAuditVerification(v)
	if out != nil {
		out.Status = "exporter-reported"
	}
	return out
}

func auditPublicPath(root, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, `\`) {
		return "", errors.New("checkpoint path must be relative to ceremony/public")
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := auditRealPath(path); err != nil {
		return "", err
	}
	return path, nil
}
func auditFileDigest(path string, limit int64) (string, error) {
	raw, err := readTesseraRegularFile(path, limit, false)
	if err != nil {
		return "", errors.New("audit public evidence unavailable or oversized")
	}
	h := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", h), nil
}

// Authentication is opt-in and rooted in a caller-supplied independent key.
// No imported report can call this function or select an executable.
func verifyAuditCheckpoint(ctx context.Context, work, key, tool, record, signature string, report auditReport) (*auditVerification, error) {
	fail := &auditVerification{Status: "failed", Depth: "not-run", Progress: []string{}}
	if err := auditRealPath(work); err != nil {
		return fail, err
	}
	if err := auditRealPath(key); err != nil {
		return fail, err
	}
	root := filepath.Join(work, "ceremony", "public")
	if rel, err := filepath.Rel(root, key); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fail, errors.New("coordinator trust key must be outside the public evidence directory")
	}
	lock, err := acquireParticipantRunLock("", work)
	if err != nil {
		return fail, errors.New("audit workspace busy")
	}
	defer lock.release()
	if err := auditRealPath(root); err != nil {
		return fail, err
	}
	// The verifier can follow references within the public tree. Reject links and
	// special files before handing it that tree; keep a bounded traversal.
	count := 0
	err = filepath.WalkDir(root, func(_ string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		count++
		if count > 65536 || d.Type()&os.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			return errors.New("invalid public evidence tree")
		}
		return nil
	})
	if err != nil {
		return fail, errors.New("public evidence tree is unavailable, oversized or unsafe")
	}
	checkpoint, err := auditPublicPath(root, record)
	if err != nil {
		return fail, err
	}
	checkpointSig, err := auditPublicPath(root, signature)
	if err != nil {
		return fail, err
	}
	definition := filepath.Join(root, "ceremony.json")
	definitionSig := filepath.Join(root, "ceremony.sig")
	beforeDef, err := auditFileDigest(definition, 16<<20)
	if err != nil {
		return fail, err
	}
	beforeDefSig, err := auditFileDigest(definitionSig, 4096)
	if err != nil {
		return fail, err
	}
	beforeHeadSig, err := auditFileDigest(checkpointSig, 4096)
	if err != nil {
		return fail, err
	}
	beforeHead, err := auditFileDigest(checkpoint, 16<<20)
	if err != nil {
		return fail, err
	}
	if strings.TrimPrefix(beforeDef, "sha256:") != report.DefinitionSHA256 {
		return fail, errors.New("journal definition differs from public evidence")
	}
	keyBytes, err := readTesseraRegularFile(key, 4096, false)
	if err != nil {
		return fail, errors.New("coordinator trust key unavailable")
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(keyBytes)))
	if err != nil || len(decoded) != 32 {
		return fail, errors.New("invalid coordinator public key")
	}
	fingerprint := sha256.Sum256(decoded)
	measured, err := measuredReleaseTools(tool)
	if err != nil {
		return fail, errors.New("approved local proof tool unavailable or mismatched")
	}
	runner := func(_ string, args ...string) ([]byte, []byte, error) {
		cmd := exec.CommandContext(ctx, measured.ProofPath, args...)
		var out, stderr limitedVerificationOutput
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		return out.Bytes(), nil, err
	}
	inspector := transcript.Inspector{Executable: measured.ProofPath, CeremonyPath: definition, CeremonySignaturePath: definitionSig, CoordinatorPublicKeyPath: key, TranscriptRoot: root, Runner: runner}
	d, err := inspector.Definition()
	if err != nil || strings.TrimPrefix(d.CeremonyID, "sha256:") != report.CeremonyID {
		return fail, errors.New("independent ceremony authentication failed")
	}
	inspected, err := inspector.StoredCheckpointV4(root, checkpoint, checkpointSig)
	if err != nil {
		return fail, errors.New("checkpoint ancestry verification failed or evidence is missing")
	}
	c := inspected.Checkpoint
	if strings.TrimPrefix(c.CeremonyID, "sha256:") != report.CeremonyID || c.Definition.Record.Digest.SHA256 != beforeDef || c.Definition.Signature.Digest.SHA256 != beforeDefSig || inspected.CheckpointRefs.Record.Digest.SHA256 != beforeHead || inspected.CheckpointRefs.Signature.Digest.SHA256 != beforeHeadSig {
		return fail, errors.New("verified checkpoint differs from audit evidence")
	}
	afterDef, e1 := auditFileDigest(definition, 16<<20)
	afterHead, e2 := auditFileDigest(checkpoint, 16<<20)
	afterKey, e3 := readTesseraRegularFile(key, 4096, false)
	afterDefSig, e4 := auditFileDigest(definitionSig, 4096)
	afterHeadSig, e5 := auditFileDigest(checkpointSig, 4096)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil || afterDefSig != beforeDefSig || afterHeadSig != beforeHeadSig || afterDef != beforeDef || afterHead != beforeHead || !bytes.Equal(afterKey, keyBytes) {
		return fail, errors.New("audit trust or evidence changed during verification")
	}
	v := &auditVerification{DefinitionSignatureSHA256: beforeDefSig, CheckpointSignatureSHA256: beforeHeadSig, Status: "passed", Depth: "checkpoint-structure", CeremonyID: c.CeremonyID, DefinitionSHA256: beforeDef, CheckpointSHA256: beforeHead, CoordinatorKeySHA256: fmt.Sprintf("sha256:%x", fingerprint), VerifierSHA256: "sha256:" + measured.ProofSHA256, Sequence: c.Sequence, Phase1Accepted: uint64(c.Progress.Phase1.AcceptedCount), Progress: []string{"phase1"}}
	for _, p := range []struct {
		name    string
		present bool
	}{{"phase1-closed", c.Progress.Phase1Closure != nil}, {"phase1-beacon", c.Progress.Phase1Beacon != nil}, {"phase1-sealed", c.Progress.Phase1Seal != nil}, {"phase2", c.Progress.Phase2 != nil}, {"phase2-closed", c.Progress.Phase2Closure != nil}, {"phase2-beacon", c.Progress.Phase2Beacon != nil}, {"final-candidate", c.Progress.FinalCandidate != nil}, {"release-review", c.Progress.ReleaseReview != nil}, {"final-release", c.Progress.FinalRelease != nil}, {"terminal", c.Progress.Terminal != nil}} {
		if p.present {
			v.Progress = append(v.Progress, p.name)
		}
	}
	if c.Progress.Phase2 != nil {
		v.Phase2Accepted = uint64(c.Progress.Phase2.AcceptedCount)
	}
	return v, nil
}
