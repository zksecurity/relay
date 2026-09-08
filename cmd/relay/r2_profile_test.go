package main

import (
	"strings"
	"testing"
)

func TestR2ProfileImportExcludesUnrelatedAndUnsupportedCredentials(t *testing.T) {
	raw := "[coordinator]\naws_access_key_id = " + strings.Repeat("a", 32) + "\naws_secret_access_key = " + strings.Repeat("b", 64) + "\n[unrelated]\naws_access_key_id = AKIAOTHER\naws_secret_access_key = other\n[dynamic]\ncredential_process = some-command\n"
	profiles, err := parseR2CoordinatorProfiles([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 1 || profiles["coordinator"][0] != strings.Repeat("a", 32) {
		t.Fatal("import did not isolate the supported R2 profile")
	}
	for _, bad := range []string{raw + "[coordinator]\n", "[a]\naws_access_key_id=a\naws_access_key_id=b\n", "aws_access_key_id=outside-profile\n"} {
		if _, err := parseR2CoordinatorProfiles([]byte(bad)); err == nil {
			t.Fatal("accepted ambiguous profile")
		}
	}
}
