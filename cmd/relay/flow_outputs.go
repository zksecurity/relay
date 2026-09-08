package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Only independent output files are allocated here. Protocol-layout directories
// (phase1/sealed, phase2) must not be silently relocated on a retry.
func flowIndependentOutput(task flowTask, field flowField) bool {
	if field.Kind != "path" {
		return false
	}
	if field.Flag == "out" {
		return true
	}
	if field.Flag == "out-dir" && len(task.Command) > 2 && task.Command[1] == "ops" {
		return task.Command[2] == "prepare-public-witness-receipt" || task.Command[2] == "prepare-mirror-receipt"
	}
	return field.Flag == "audit-signature" && len(task.Command) > 1 && task.Command[1] == "audit"
}

func (f *roleFlow) rememberedOutputPath(value string, includeExact bool) string {
	best, replacement := "", ""
	for key, saved := range f.state.Values {
		if !strings.HasPrefix(key, "output/") {
			continue
		}
		original := strings.TrimPrefix(key, "output/")
		if (includeExact && value == original) || strings.HasPrefix(value, original+"/") {
			if len(original) > len(best) {
				best, replacement = original, saved
			}
		}
	}
	if best != "" {
		return replacement + strings.TrimPrefix(value, best)
	}
	return value
}

func (f *roleFlow) freshOutputDefault(value string) (string, error) {
	if value == "" || f.state.Profile.Work == "" {
		return value, nil
	}
	if !strings.HasPrefix(value, "/work/") {
		return "", errors.New("workflow output must be inside your work folder")
	}
	ext := filepath.Ext(value)
	stem := strings.TrimSuffix(value, ext)
	for n := 1; n <= 1000; n++ {
		candidate := value
		if n > 1 {
			candidate = stem + "-" + strconv.Itoa(n) + ext
		}
		_, err := os.Lstat(flowHostPath(f.state.Profile, candidate))
		if errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("check fresh output: %w", err)
		}
	}
	return "", errors.New("too many existing outputs; review retained files before another action")
}

// These are local navigation hints, not authenticated state or evidence of
// acceptance. The next command still verifies the supplied files independently.
func (f *roleFlow) rememberSuccessfulOutputs(task flowTask, command []string) {
	for _, field := range task.Fields {
		if !flowIndependentOutput(task, field) || field.Default == "" {
			continue
		}
		for n, arg := range command {
			if arg == "--"+field.Flag && n+1 < len(command) {
				f.state.Values["output/"+field.Default] = command[n+1]
			}
		}
	}
}
