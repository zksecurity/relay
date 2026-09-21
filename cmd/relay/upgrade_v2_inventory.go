package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zksecurity/relay/internal/upgrade"
)

type upgradeInventoryFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type upgradeInventory struct {
	Files       []upgradeInventoryFile `json:"files"`
	Kinds       []string               `json:"kinds"`
	Pending     []string               `json:"pending"`
	HistoryGaps []string               `json:"history_gaps,omitempty"`
}

// Inventory records fingerprints, never credential/key contents. It neither
// claims an output is verified nor modifies the source journal. Ordinary
// workflow recovery still authenticates exact bytes before any side effect.
func upgradeV2Inventory(p guidedProfile, d upgrade.DeclarationV2) (upgradeInventory, error) {
	inv := upgradeInventory{Kinds: upgradeV2RoleKinds(p.Role)}
	if inv.Kinds == nil {
		return inv, errors.New("unsupported role inventory")
	}
	// Activity is not protocol evidence or proof of a clean exit. Preserve its
	// bytes and surface missing/incomplete history without inventing completion.
	_, gaps, err := readAuditActivity(p.Work)
	if err != nil {
		return inv, fmt.Errorf("read retained activity: %w", err)
	}
	inv.HistoryGaps = gaps
	var journal workflowV4State
	journalPath := filepath.Join(p.Work, "workflow-v4/state.json")
	if err := readWorkflowV4JSON(journalPath, &journal); err == nil {
		if journal.Marker.Binding.Work != p.Work || journal.Marker.Binding.Role != p.Role || journal.Marker.Binding.Name != p.Name {
			return inv, errors.New("retained journal belongs to another role")
		}
		if err := validateWorkflowV4State(journal, journal.Marker.Binding, journalPath); err != nil {
			return inv, err
		}
		var marker workflowV4Marker
		if err := readWorkflowV4JSON(filepath.Join(p.Work, ".relay-workspace-v4.json"), &marker); err != nil {
			return inv, err
		}
		a, _ := json.Marshal(marker)
		b, _ := json.Marshal(journal.Marker)
		if string(a) != string(b) {
			return inv, errors.New("workspace marker differs from retained journal")
		}
		for _, op := range journal.Operations {
			kind, err := upgradeV2KindForOperation(op.Plan.Kind)
			if err != nil {
				return inv, err
			}
			inv.Kinds = append(inv.Kinds, kind)
			if !workflowV4OperationResolved(op.Status) {
				inv.Pending = append(inv.Pending, op.Plan.Kind+": "+op.Status+" (reverify retained output; do not recompute)")
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return inv, err
	}
	// Include all work, not only the generic journal. Unknown top-level folders
	// must be reviewed rather than hidden behind an empty state.Operations.
	allowed := map[string]bool{"ceremony": true, "workflow-v4": true, "coordinator-setup": true, "role-preparation": true, "my-enrollment": true, "custody": true, "runs": true, "approved-tools": true, "enrollment.json": true, "enrollment.sig": true, "enrollment-disclosure.txt": true, "environment.json": true, ".relay-workspace-v4.json": true}
	allowed[".relay"] = true // retained rollback/fork high-water records
	err = filepath.WalkDir(p.Work, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == p.Work {
			return nil
		}
		rel, err := filepath.Rel(p.Work, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		first := strings.Split(rel, "/")[0]
		if first == diagnosticDirectory {
			if rel == diagnosticDirectory {
				return nil
			}
			if rel != diagnosticDirectory+"/"+auditActivityFile {
				if e.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if first == ".relay-upgrades" || first == "diagnostics" || first == ".relay-workspace.lock" || first == "relay-upgrade.json" {
			if e.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !allowed[first] && first != diagnosticDirectory {
			return fmt.Errorf("unrecognized retained workspace entry %q; preserve it for review", first)
		}
		if first == "workflow-v4" {
			parts := strings.Split(rel, "/")
			if len(parts) > 1 {
				known := map[string]bool{"state.json": true, "coordinator": true, "release": true, "beacons": true, "scopes": true, "commits": true, "inputs": true, "results": true, "temporary": true, "staging": true, ".relay-workspace.lock": true}
				name := parts[1]
				if !known[name] && !(len(parts) == 2 && strings.HasSuffix(name, ".json") && (strings.HasPrefix(name, "contributor-") || strings.HasPrefix(name, "execution-"))) {
					return fmt.Errorf("unknown retained workflow state %q", name)
				}
			}
		}
		if e.Type()&os.ModeSymlink != 0 {
			return errors.New("symlink in retained workspace")
		}
		if e.IsDir() {
			return nil
		}
		if !e.Type().IsRegular() {
			return errors.New("nonregular retained workspace input")
		}
		if len(inv.Files) >= 100000 {
			return errors.New("upgrade inventory exceeds file limit")
		}
		if strings.HasSuffix(rel, "-intent.json") && strings.HasPrefix(rel, "workflow-v4/coordinator/") {
			var intent workflowV4CoordinatorIntent
			if err := readWorkflowV4JSON(path, &intent); err != nil {
				return err
			}
			if intent.Schema != workflowV4CoordinatorIntentSchema {
				return errors.New("unknown coordinator intent")
			}
			if intent.Action != "allocate" && intent.Action != "accept" && intent.Action != "reject" {
				return errors.New("unsupported coordinator intent action")
			}
			if _, err := pathWithin(p.Work, intent.OutputDir, "/work"); err != nil {
				return err
			}
			inv.Pending = append(inv.Pending, "coordinator "+intent.Action+": verify retained checkpoint against accepted ancestry")
		}
		if strings.HasPrefix(rel, "workflow-v4/commits/") && strings.HasSuffix(rel, ".json") {
			var record coordinatorCommitJournalRecord
			if err := readWorkflowV4JSON(path, &record); err != nil {
				return err
			}
			if err := record.validate(); err != nil {
				return err
			}
			inv.Pending = append(inv.Pending, "publication: "+string(record.Stage)+" (reconcile exact remote bytes before advancing)")
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		before, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		h := sha256.New()
		size, err := io.Copy(h, f)
		after, statErr := f.Stat()
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if statErr != nil {
			return statErr
		}
		if closeErr != nil {
			return closeErr
		}
		if size != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return errors.New("retained input changed during inventory")
		}
		inv.Files = append(inv.Files, upgradeInventoryFile{rel, hex.EncodeToString(h.Sum(nil)), size})
		return nil
	})
	if err != nil {
		return inv, err
	}
	slices.Sort(inv.Kinds)
	inv.Kinds = slices.Compact(inv.Kinds)
	if err := d.Cover(nil, inv.Kinds); err != nil {
		return inv, err
	}
	return inv, nil
}

func (i upgradeInventory) digest() string { raw, _ := json.Marshal(i); return upgradeBytesHash(raw) }
