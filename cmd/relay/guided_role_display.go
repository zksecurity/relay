package main

import (
	"errors"
	"fmt"
	"slices"
)

// Presentation context only. Never use this value for profile lookup, image
// selection, mounts, permissions, signed records, or assignment verification.
func guidedRoleDisplay(executionRole, displayRole string, command []string) (string, error) {
	labels := map[string]string{"coordinator": "Coordinator", "participant": "Participant", "witness": "Witness", "mirror": "Mirror", "auditor": "Auditor", "release-signer": "Release-signer", "upload-station": "Upload-station"}
	if displayRole != "" && (executionRole != "decision-signer" || labels[displayRole] == "") {
		return "", errors.New("--display-role requires an internal decision-signer profile and a known ceremony role")
	}
	if executionRole != "decision-signer" {
		return fmt.Sprintf("Role: %s\n", executionRole), nil
	}
	if len(command) >= 3 && slices.Equal(command[:3], []string{"mpc-ceremony", "ops", "prepare-enrollment"}) {
		requestedRole := commandValue(command, "role")
		switch requestedRole {
		case "public-witness":
			requestedRole = "witness"
		case "mirror-operator":
			requestedRole = "mirror"
		}
		if labels[requestedRole] != "" {
			if displayRole != "" && displayRole != requestedRole {
				return "", errors.New("display role differs from the enrollment role; no operation approved")
			}
			displayRole = requestedRole
		}
	}
	label := "see signed record"
	if displayRole != "" {
		label = labels[displayRole]
	}
	return "Ceremony role: " + label + "\nExecution environment: Network-disabled signing container\n", nil
}
