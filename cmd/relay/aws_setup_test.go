package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAWSExistingRoleCheckedBeforeCloudWrites(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("requires jq")
	}
	script, err := filepath.Abs("../../scripts/storage-setup/setup-aws.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "wrong-trust", "short-duration", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			stub := `#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "$CALLS"
case "$*" in
 'configure list-profiles') echo test ;;
 *'sts get-caller-identity'*) echo '{"Account":"123456789012","Arn":"arn:aws:iam::123456789012:user/test"}' ;;
 *'iam get-role'*)
  [[ "$SCENARIO" != missing ]] || exit 1
  principal=arn:aws:iam::123456789012:user/test
  ttl=3600
  [[ "$SCENARIO" != wrong-trust ]] || principal=arn:aws:iam::123456789012:user/other
  [[ "$SCENARIO" != short-duration ]] || ttl=900
  jq -n --arg principal "$principal" --argjson ttl "$ttl" '{Role:{Arn:"arn:aws:iam::123456789012:role/test-inbox-grant",MaxSessionDuration:$ttl,AssumeRolePolicyDocument:{Statement:[{Effect:"Allow",Action:"sts:AssumeRole",Principal:{AWS:$principal}}]}}}' ;;
 *'s3api head-bucket'*) exit 1 ;;
 *'s3api create-bucket'*) echo 'STOP_BEFORE_WRITE' >&2; exit 91 ;;
 *) echo 'UNEXPECTED_CALL' >&2; exit 92 ;;
esac
`
			if err := os.WriteFile(filepath.Join(root, "aws"), []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, "setup.env")
			if err := os.WriteFile(config, []byte("AWS_PROFILE=test\nAWS_REGION=us-east-1\nRESOURCE_PREFIX=test\nUSE_EXISTING_GRANT_ROLE=yes\nCONFIRM_CREATE=yes\n"), 0600); err != nil {
				t.Fatal(err)
			}
			calls := filepath.Join(root, "calls")
			cmd := exec.Command("bash", script, config)
			cmd.Env = append(os.Environ(), "PATH="+root+":"+os.Getenv("PATH"), "CALLS="+calls, "SCENARIO="+scenario)
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("expected fixture stop")
			}
			raw, _ := os.ReadFile(calls)
			reachedWrite := strings.Contains(string(raw), "s3api create-bucket")
			if reachedWrite != (scenario == "valid") {
				t.Fatalf("unexpected write preflight outcome: %s\n%s", raw, output)
			}
			if strings.Contains(string(output), "UNEXPECTED_CALL") {
				t.Fatalf("unexpected command: %s", output)
			}
		})
	}
}
