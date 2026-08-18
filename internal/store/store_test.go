package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTemporaryCredentialsReachOnlyChildEnvironment(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	envPath := filepath.Join(dir, "env")
	executable := filepath.Join(dir, "aws")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$RELAY_TEST_ARGS"
printf '%s\n%s\n%s\n' "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_SESSION_TOKEN" > "$RELAY_TEST_ENV"
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RELAY_TEST_ARGS", argsPath)
	t.Setenv("RELAY_TEST_ENV", envPath)
	local := filepath.Join(dir, "body")
	if err := os.WriteFile(local, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := Client{
		Endpoint: "https://example.invalid", Region: "auto", Bucket: "inbox",
		Credentials: &Credentials{AccessKeyID: "temporary-id", SecretAccessKey: "temporary-secret", SessionToken: "temporary-token"},
	}
	if err := client.PutNoReplace("scoped/file", local); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"temporary-id", "temporary-secret", "temporary-token"} {
		if strings.Contains(string(args), secret) {
			t.Fatalf("temporary credential leaked into argv: %q", args)
		}
	}
	if strings.Contains(string(args), "--profile") || !strings.Contains(string(args), "--if-none-match\n*\n") {
		t.Fatalf("unexpected aws argv: %q", args)
	}
	environment, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(environment) != "temporary-id\ntemporary-secret\ntemporary-token\n" {
		t.Fatalf("child credential environment = %q", environment)
	}
}

func TestListFollowsContinuationTokens(t *testing.T) {
	dir := t.TempDir()
	executable := filepath.Join(dir, "aws")
	script := `#!/bin/sh
case " $* " in
  *" --continuation-token next-page "*)
    printf '%s\n' '{"Contents":[{"Key":"scope/two","Size":2}],"IsTruncated":false}'
    ;;
  *)
    printf '%s\n' '{"Contents":[{"Key":"scope/one","Size":1}],"IsTruncated":true,"NextContinuationToken":"next-page"}'
    ;;
esac
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	objects, err := (Client{Bucket: "inbox"}).List("scope/")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != 2 || objects[0].Key != "scope/one" || objects[1].Key != "scope/two" {
		t.Fatalf("objects = %#v", objects)
	}
}
