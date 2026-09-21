package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/upgrade"
)

func TestUpgradeApprovalReleaseDefaultsAndValidation(t *testing.T) {
	target, authority := strings.Repeat("b", 40), strings.Repeat("c", 40)
	for _, tc := range []struct{ tag, want string }{{"", target}, {"role-images-" + authority, authority}} {
		got, err := upgradeApprovalCommit(tc.tag, target)
		if err != nil || got != tc.want {
			t.Fatal(got, err)
		}
	}
	for _, tag := range []string{"main", "role-images-../outside", "https://example.com/approval"} {
		if _, err := upgradeApprovalCommit(tag, target); err == nil {
			t.Fatal("invalid approval accepted")
		}
	}
}

func TestUpgradeReviewedPublishedAssets(t *testing.T) {
	s, d := testUpgradeV2(t, "coordinator")
	d.OnlineImage = d.OriginalImage
	testUpgradeV2Report(t, &s, &d)
	var q upgrade.QualificationV2
	if err := json.Unmarshal(s.Qualification, &q); err != nil {
		t.Fatal(err)
	}
	q.Schema = upgrade.CleanExitQualificationSchema
	q.Passed = append([]string{}, upgrade.CleanExitQualificationChecks...)
	predecessor := []byte("test-only predecessor executable")
	q.Predecessors[d.SourceApp] = "sha256:" + upgradeBytesHash(predecessor)
	binary, err := os.ReadFile(s.Launcher)
	if err != nil {
		t.Fatal(err)
	}
	report, _ := json.Marshal(q)
	asset := "relay-" + strings.ReplaceAll(d.Host, "/", "-")
	data := map[string][]byte{
		d.SourceApp + "/" + asset:                             predecessor,
		d.OriginalRelease + "/relay-role-images.release.json": s.OriginalMap,
		d.TargetApp + "/relay-role-images.release.json":       s.TargetMap,
		d.TargetApp + "/" + asset:                             binary,
	}
	get := func(commit, name string) ([]byte, error) {
		raw, ok := data[commit+"/"+name]
		if !ok {
			return nil, errors.New("unverified asset")
		}
		return raw, nil
	}
	files, err := generateReviewedPublishedUpgrade(d, report, get)
	if err != nil {
		t.Fatal(err)
	}
	produced, err := upgrade.DecodeV2(files[d.AssetName()])
	if err != nil || produced.TargetApp != d.TargetApp {
		t.Fatal("approval changed target", err)
	}
	if _, err := generateReviewedPublishedUpgrade(d, report, func(string, string) ([]byte, error) { return nil, errors.New("provenance rejected") }); err == nil {
		t.Fatal("failed provenance accepted")
	}
	for _, key := range []string{d.SourceApp + "/" + asset, d.TargetApp + "/" + asset} {
		old := data[key]
		data[key] = []byte("substituted binary")
		if _, err := generateReviewedPublishedUpgrade(d, report, get); err == nil {
			t.Fatal("changed binary accepted")
		}
		data[key] = old
	}
	q.Role = "participant"
	bad, _ := json.Marshal(q)
	if _, err := generateReviewedPublishedUpgrade(d, bad, get); err == nil {
		t.Fatal("wrong report tuple accepted")
	}
	if _, err := generateReviewedPublishedUpgrade(d, nil, get); err == nil {
		t.Fatal("missing report accepted")
	}
}

func TestUpgradeApprovalSelectionPreservesHistory(t *testing.T) {
	s, _ := testUpgradeV2(t, "coordinator")
	s.ApprovalRelease = "role-images-" + strings.Repeat("c", 40)
	if err := upgradeV2Activate(s, ""); err != nil {
		t.Fatal(err)
	}
	history, _, err := upgradeV2ReadHistory(s.Profile.Work)
	if err != nil || history[0].ApprovalRelease != s.ApprovalRelease {
		t.Fatal("approval origin lost", err)
	}
}

func TestUpgradeReviewedPublishedEmptyPolicy(t *testing.T) {
	root := t.TempDir()
	policy := filepath.Join(root, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"schema":"relay-upgrade-policy/v2","pairs":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "out")
	if err := runUpgradeManifestsV2([]string{"--reviewed-published", "--policy", policy, "--reports", filepath.Join(root, "absent"), "--out", out}); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(out)
	if err != nil || len(files) != 0 {
		t.Fatal("empty policy enabled an update", err)
	}
	_, d := testUpgradeV2(t, "coordinator")
	raw, err := json.Marshal(upgradePolicyV2{Schema: "relay-upgrade-policy/v2", Pairs: []upgrade.DeclarationV2{d}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policy, raw, 0600); err != nil {
		t.Fatal(err)
	}
	err = runUpgradeManifestsV2([]string{"--reviewed-published", "--policy", policy, "--reports", filepath.Join(root, "absent"), "--out", filepath.Join(root, "no-output")})
	if err == nil || !strings.Contains(err.Error(), "missing reviewed local qualification report") {
		t.Fatal("missing report was not rejected", err)
	}
}

func TestUpgradeOfflineApprovalOrigin(t *testing.T) {
	root := t.TempDir()
	b, c := strings.Repeat("b", 40), strings.Repeat("c", 40)
	bundle := filepath.Join(root, "bundle")
	for commit, name := range map[string]string{b: "relay-role-images.release.json", c: "upgrade-test.json"} {
		dir := filepath.Join(bundle, commit)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for suffix, value := range map[string]string{"": "test public asset", ".sigstore.jsonl": "test proof"} {
			if err := os.WriteFile(filepath.Join(dir, name+suffix), []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	trust := filepath.Join(root, "trust.json")
	if err := os.WriteFile(trust, []byte("independent test root"), 0600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
test "$1" = attestation && test "$2" = verify || exit 91
file="$3"
while [ "$#" -gt 0 ]; do
  if [ "$1" = --source-digest ]; then shift; digest="$1"; fi
  shift
done
case "$file" in
  */` + b + `/relay-role-images.release.json) test "$digest" = '` + b + `' ;;
  */` + c + `/upgrade-test.json) test "$digest" = '` + c + `' ;;
  *) exit 92 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	a, cleanup, err := newUpgradeAssets(bundle, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, err := a.get(c, "upgrade-test.json"); err != nil {
		t.Fatal("approval provenance domain", err)
	}
	if _, err := a.get(b, "relay-role-images.release.json"); err != nil {
		t.Fatal("app provenance domain", err)
	}
	if _, err := a.get(b, "upgrade-test.json"); err == nil {
		t.Fatal("silently searched another approval release")
	}
}
