package main

import (
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

//go:embed testdata/legacy-definition/main.go
var legacyDefinitionAuthor string

func requirePinnedTesseraProof(t *testing.T, binary string) string {
	t.Helper()
	asset, commit, _, err := pinnedProofAsset(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := setupFileHash(binary)
	if err != nil || actual != asset.SHA256 {
		t.Fatal("test executable differs from embedded release pin", err)
	}
	return commit
}

// Only generated temporary rehearsal inputs are passed here. Imported external
// fixtures stay immutable. The unchanged pinned executable authenticates output
// in the calling test; the helper does not replace the verifier.
func authorLegacyTesseraDefinition(t *testing.T, binary, generated, rehearsalKey string) string {
	t.Helper()
	commit := requirePinnedTesseraProof(t, binary)
	raw, err := os.ReadFile(filepath.Join(generated, "ceremony.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Schema string `json:"schema"`
		Mode   string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if d.Mode != "rehearsal" {
		t.Fatal("legacy fixture author requires rehearsal")
	}
	if d.Schema == "proof-tool-mpc-ceremony-definition-v2" {
		return generated
	}
	if d.Schema != "proof-tool-mpc-ceremony-definition-v3" {
		t.Fatal("unsupported generated fixture schema", d.Schema)
	}
	scratch := t.TempDir()
	source := filepath.Join(scratch, "proof-source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	run := func(directory, program string, args ...string) string {
		t.Helper()
		c := exec.Command(program, args...)
		c.Dir = directory
		output, err := c.CombinedOutput()
		if err != nil {
			t.Fatalf("fixture dependency %s failed: %v\n%s", program, err, output)
		}
		return strings.TrimSpace(string(output))
	}
	run(source, "git", "init", "--quiet")
	run(source, "git", "fetch", "--quiet", "--depth=1", "https://github.com/zksecurity/proof-tool.git", commit)
	run(source, "git", "checkout", "--quiet", "--detach", "FETCH_HEAD")
	if actual := run(source, "git", "rev-parse", "HEAD"); actual != commit {
		t.Fatal("fixture source differs from pinned proof release")
	}
	run(source, "git", "diff", "--exit-code", "HEAD", "--")
	run(source, "bash", "scripts/bootstrap-vendor.sh")
	bridge := filepath.Join(source, "internal", "mpcceremony", "testdata", "relay-legacy-definition")
	if err := os.Mkdir(bridge, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bridge, "main.go"), []byte(legacyDefinitionAuthor), 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(scratch, "author-legacy-definition")
	run(source, "go", "build", "-mod=vendor", "-o", helper, "./internal/mpcceremony/testdata/relay-legacy-definition")
	output := filepath.Join(scratch, "legacy")
	run(scratch, helper, filepath.Join(generated, "ceremony.json"), rehearsalKey, output)
	return output
}
