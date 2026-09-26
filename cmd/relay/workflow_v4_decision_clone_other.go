//go:build !darwin && !linux

package main

func workflowV4CloneDecisionInput(source, target string) (bool, error) {
	return false, nil
}
