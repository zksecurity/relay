package main

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestReleaseVersionMapping(t *testing.T) {
	commit := strings.Repeat("a", 40)
	for _, tc := range []struct {
		raw, version string
		ok           bool
	}{
		{"v0.2.0\n" + commit + "\n", "v0.2.0", true},
		{"v0.2.0\n" + commit + "\n", "v0.2.1", false},
		{"v00.2.0\n" + commit + "\n", "v00.2.0", false},
		{"v0.2.0\n" + commit + "\nextra", "v0.2.0", false},
		{"v0.2.0\n../../escape\n", "v0.2.0", false},
	} {
		got, err := parseVersionMapping([]byte(tc.raw), tc.version)
		if (err == nil) != tc.ok || (tc.ok && got != commit) {
			t.Fatalf("mapping %q: %q %v", tc.raw, got, err)
		}
	}
}

func TestReleaseVersionBoundary(t *testing.T) {
	canonical := "role-images-" + strings.Repeat("a", 40)
	input := []string{"ceremony", "prepare", "--release=v0.2.0", "--approval-release", "v0.2.1", "--", "tool", "--release", "v0.2.0"}
	want := []string{"ceremony", "prepare", "--release=" + canonical, "--approval-release", canonical, "--", "tool", "--release", "v0.2.0"}
	calls := 0
	got, err := normalizeReleaseVersions(input, func(string) (string, error) { calls++; return canonical, nil })
	if err != nil || calls != 2 || !reflect.DeepEqual(got, want) || input[2] != "--release=v0.2.0" {
		t.Fatal(got, err, calls)
	}
	_, err = normalizeReleaseVersions(input, func(string) (string, error) { return "", errors.New("unattested mapping") })
	if err == nil {
		t.Fatal("accepted unattested mapping")
	}
	_, err = normalizeReleaseVersions([]string{"--release", canonical}, func(string) (string, error) { t.Fatal("legacy release resolved remotely"); return "", nil })
	if err != nil {
		t.Fatal(err)
	}
}
