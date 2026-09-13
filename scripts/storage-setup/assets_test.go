package storagesetup

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAWSHelperRejectsChangedAccountBeforeWrites(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("requires jq")
	}
	for _, mismatch := range []string{"account", "identity"} {
		t.Run(mismatch, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range []string{"setup-aws.sh", "coordinator-settings.sh"} {
				raw, err := AWS.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			stub := `#!/bin/sh
case "$*" in
  'configure list-profiles') echo test-account;;
  '--profile test-account --region us-east-1 sts get-caller-identity --output json')
    echo '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/ceremony"}';;
  *) echo 'UNEXPECTED AWS CALL'; exit 9;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "aws"), []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			config := "AWS_PROFILE=test-account\nAWS_REGION=us-east-1\nRESOURCE_PREFIX=relay-test\nGRANT_ROLE_MAX_TTL=1h\nCONFIRM_CREATE=yes\n"
			if mismatch == "account" {
				config += "EXPECTED_ACCOUNT=999999999999\n"
			} else {
				config += "EXPECTED_ACCOUNT=123456789012\nEXPECTED_CALLER_ARN=arn:aws:iam::123456789012:user/other\n"
			}
			path := filepath.Join(dir, "approved.env")
			if err := os.WriteFile(path, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", filepath.Join(dir, "setup-aws.sh"), path)
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			raw, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(raw), "changed after review; no resources changed") || strings.Contains(string(raw), "UNEXPECTED AWS CALL") {
				t.Fatalf("guard failed: %v %s", err, raw)
			}
		})
	}
}
