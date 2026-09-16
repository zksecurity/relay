package main

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// Network transfers and coordinated commits use typed in-process handlers,
// never exec of these dispatch tokens. Each handler must consume the exact
// plan. Child signing/computation argv is checked separately below.
func validateWorkflowV4Command(p workflowV4OperationPlan, b workflowV4Binding) error {
	switch p.Kind {
	case "download-outbound", "download-receipt", "download-candidate", "upload-receipt", "upload-candidate", "issue-grant", "commit-outbound", "commit-receipt", "commit-candidate":
		if !reflect.DeepEqual(p.Command, []string{"relay-internal", p.Kind}) {
			return errors.New("V4 internal action cannot execute an arbitrary command")
		}
		return nil
	}
	prefix := []string{"mpc-ceremony", "ops", "sign"}
	if p.Kind == "contribute" {
		prefix = []string{"mpc-ceremony", p.Scope.Phase, "contribute"}
	}
	if len(p.Command) < len(prefix) || !reflect.DeepEqual(p.Command[:len(prefix)], prefix) {
		return errors.New("V4 command does not match its operation kind")
	}
	flags := make(map[string]string)
	for n := len(prefix); n < len(p.Command); n++ {
		flag := p.Command[n]
		if !strings.HasPrefix(flag, "--") || strings.Contains(flag, "=") {
			return errors.New("V4 command requires explicit named arguments")
		}
		if _, exists := flags[flag]; exists {
			return errors.New("duplicate V4 command argument")
		}
		if flag == "--reviewed" {
			flags[flag] = "true"
			continue
		}
		n++
		if n == len(p.Command) || p.Command[n] == "" {
			return errors.New("missing V4 command argument value")
		}
		flags[flag] = p.Command[n]
	}
	inputByFlag := []string{"--ceremony", "--ceremony-signature", "--coordinator-public-key-file"}
	if p.Kind == "contribute" {
		inputByFlag = append(inputByFlag, "--chain", "--chain-signature", "--environment")
		if p.Scope.Phase == "phase2" {
			inputByFlag = append(inputByFlag, "--phase1-seal", "--phase1-seal-signature")
		}
	} else {
		inputByFlag = append(inputByFlag, "--record")
	}
	inputRefs := make(map[string]workflowV4Input)
	for _, input := range p.Inputs {
		path, err := workflowV4ContainerPath(p.Runtime, input.Path)
		if err != nil {
			return err
		}
		inputRefs[path] = input
	}
	allowed := make(map[string]bool)
	for _, flag := range inputByFlag {
		allowed[flag] = true
		input, ok := inputRefs[flags[flag]]
		if !ok {
			return errors.New("V4 command input is not an exact retained file")
		}
		switch flag {
		case "--ceremony":
			if input.Ref != b.Definition.Record {
				return errors.New("V4 command uses another definition")
			}
		case "--ceremony-signature":
			if input.Ref != b.Definition.Signature {
				return errors.New("V4 command uses another definition signature")
			}
		case "--chain":
			if input.Ref != p.Predecessor.Record {
				return errors.New("V4 command uses another predecessor")
			}
		case "--chain-signature":
			if input.Ref != p.Predecessor.Signature {
				return errors.New("V4 command uses another predecessor signature")
			}
		}
	}
	outputFlag, keyFlag := "--out", "--signing-key"
	if p.Kind == "contribute" {
		outputFlag, keyFlag = "--out-dir", "--participant-signing-key"
	}
	allowed[outputFlag], allowed[keyFlag] = true, true
	if len(p.Outputs) != 1 {
		return errors.New("V4 child command requires exactly one declared output")
	}
	output, err := workflowV4ContainerPath(p.Runtime, p.Outputs[0])
	if err != nil {
		return err
	}
	if flags[outputFlag] != output {
		return errors.New("V4 command output differs from its declared output")
	}
	key := flags[keyFlag]
	if p.Runtime.Mounts["/keys"] == "" || key != "/keys/signing.hex" {
		return errors.New("V4 child must use the role's protected signing key")
	}
	if p.Kind == "contribute" {
		for _, flag := range []string{"--transcript-dir", "--participant-id", "--contributed-at"} {
			allowed[flag] = true
		}
		if flags["--participant-id"] != p.Scope.ParticipantID {
			return errors.New("V4 command participant differs from the turn")
		}
		timestamp, err := time.Parse(time.RFC3339, flags["--contributed-at"])
		if err != nil || timestamp.IsZero() || timestamp.UTC().Format(time.RFC3339) != flags["--contributed-at"] {
			return errors.New("V4 contribution needs an exact UTC timestamp")
		}
		root := flags["--transcript-dir"]
		if !strings.HasPrefix(root, "/work/") || filepath.Clean(root) != root {
			return errors.New("V4 transcript root must be retained under work")
		}
		for _, flag := range []string{"--chain", "--chain-signature"} {
			if _, err := pathWithin(root, flags[flag], "/"); err != nil {
				return errors.New("V4 predecessor is outside the declared transcript root")
			}
		}
	} else {
		for _, flag := range []string{"--record-type", "--reviewed", "--reviewed-sha256"} {
			allowed[flag] = true
		}
		kind := "receipt"
		if p.Kind == "sign-return" {
			kind = "handoff"
		}
		if flags["--record-type"] != kind || flags["--reviewed"] != "true" || flags["--reviewed-sha256"] != strings.TrimPrefix(inputRefs[flags["--record"]].Ref.Digest.SHA256, "sha256:") {
			return errors.New("V4 signing command must bind the exact reviewed record")
		}
	}
	for flag := range flags {
		if !allowed[flag] {
			return errors.New("unsupported V4 child command argument")
		}
	}
	return nil
}

func workflowV4ContainerPath(runtime workflowV4Runtime, path string) (string, error) {
	for destination, source := range runtime.Mounts {
		if mapped, err := pathWithin(source, path, destination); err == nil {
			return mapped, nil
		}
	}
	return "", errors.New("V4 command path has no approved runtime mount")
}
