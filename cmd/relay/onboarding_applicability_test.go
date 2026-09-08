package main

import "testing"

func TestOnboardingNotApplicable(t *testing.T) {
	for _, role := range []string{"participant", "witness", "mirror", "auditor", "release-signer", "upload-station"} {
		for _, choice := range []string{"1", "2", "3", "4", "5", "6", "7", "8", "0"} {
			want := role == "upload-station" && (choice == "2" || choice == "7") || role == "release-signer" && choice == "4"
			if got := onboardingNotApplicable(role, choice) != ""; got != want {
				t.Errorf("role %s choice %s: inapplicable=%v, want %v", role, choice, got, want)
			}
		}
	}
}
