package main

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func TestAWSGrantDefaultsRespectRoleMaximum(t *testing.T) {
	l := flowGrantLimits{"AWS", 15 * time.Minute, time.Hour}
	if got := l.defaultValue("credential-ttl", "2h", time.Hour); got != "1h" {
		t.Fatal(got)
	}
	if got := l.defaultValue("minimum-remaining", "1h", time.Hour); got != "30m" {
		t.Fatal(got)
	}
	if err := l.validate("credential-ttl", "2h", time.Hour); err == nil {
		t.Fatal("oversized grant accepted")
	}
	if err := l.validate("credential-ttl", "14m", time.Hour); err == nil {
		t.Fatal("too short grant accepted")
	}
	if err := l.validate("minimum-remaining", "1h", time.Hour); err == nil {
		t.Fatal("unusable remaining-time requirement accepted")
	}
}

func TestGrantPromptUsesSelectedStorageAndTTL(t *testing.T) {
	for _, provider := range []string{"aws", "r2"} {
		t.Run(provider, func(t *testing.T) {
			f := flowFixture(t)
			f.state.Profile.Work = t.TempDir()
			config := access.StorageConfig{Schema: access.StorageConfigSchema, Provider: provider, CeremonyID: "sha256:" + strings.Repeat("1", 64), PublishedBucket: "public", InboxBucket: "private", PublishedBaseURL: "https://example.invalid", CoordinatorProfile: "test", Region: "test", IssuerProfile: "test", GrantRoleARN: "test", GrantRoleMaxTTL: "1h", CeremonyPath: "/work/ceremony.json", CeremonySignature: "/work/ceremony.sig", CoordinatorPublicKey: "/trust/coordinator.hex", CeremonyBinary: "mpc-ceremony", AccountID: "test", ParentAccessKeyID: "test", Endpoint: "https://example.invalid"}
			// An imported fractional maximum must not become an invalid default.
			config.GrantRoleMaxTTL = "1h500ms"
			if err := saveJSONAtomic(filepath.Join(f.state.Profile.Work, "storage.json"), config); err != nil {
				t.Fatal(err)
			}
			task := flowTask{ID: "grant", Command: []string{"relay", "coordinator", "grant"}, Fields: []flowField{ff("storage", "Storage", "/work/storage.json"), ft("credential-ttl", "Grant lifetime", "2h"), ft("minimum-remaining", "Minimum time remaining", "1h")}}
			// Invalid lifetime and remaining time must reprompt before producing a command.
			f.ui.input = bufio.NewReader(strings.NewReader("\n999h\n30m\n30m\n5m\n"))
			command, err := f.command(task)
			if err != nil {
				t.Fatal(err)
			}
			if commandValue(command, "credential-ttl") != "30m" || commandValue(command, "minimum-remaining") != "5m" {
				t.Fatal(command)
			}
			output := f.ui.output.(*bytes.Buffer).String()
			rangeText := "AWS configured range: 15m to 1h, inclusive; whole seconds"
			if provider == "r2" {
				rangeText = "R2 configured range: 1s to 168h, inclusive; whole seconds"
			}
			if !strings.Contains(output, rangeText) || !strings.Contains(output, "more than 0 and less than 30m") || !strings.Contains(output, "not extra time") {
				t.Fatal(output)
			}
			if strings.Index(output, rangeText) > strings.Index(output, "grant lifetime must") {
				t.Fatal("range only shown after validation error")
			}
		})
	}
}

func TestGrantRangesDisplayedAndEnforced(t *testing.T) {
	for _, l := range []flowGrantLimits{{"AWS", 15 * time.Minute, time.Hour}, {"AWS", 15 * time.Minute, 4 * time.Hour}, {"R2", time.Second, 168 * time.Hour}} {
		label := l.label("credential-ttl", "Grant lifetime", l.maximum)
		for _, part := range []string{l.provider, displayGrantDuration(l.minimum) + " to " + displayGrantDuration(l.maximum), "inclusive", "whole seconds"} {
			if !strings.Contains(label, part) {
				t.Fatal(label, part)
			}
		}
		for _, valid := range []time.Duration{l.minimum, l.maximum} {
			if err := l.validate("credential-ttl", valid.String(), l.maximum); err != nil {
				t.Fatal(err)
			}
		}
		for _, invalid := range []string{"", "bad", "0", "-1s", (l.minimum - time.Nanosecond).String(), (l.maximum + time.Second).String(), (l.minimum + time.Millisecond).String()} {
			if l.validate("credential-ttl", invalid, l.maximum) == nil {
				t.Fatal("accepted", invalid)
			}
		}
		if !strings.Contains(l.label("minimum-remaining", "Minimum time remaining", 30*time.Minute), "more than 0 and less than 30m") {
			t.Fatal("remaining label ignores chosen TTL")
		}
		for _, invalid := range []string{"0", "-1s", "30m", "31m"} {
			if l.validate("minimum-remaining", invalid, 30*time.Minute) == nil {
				t.Fatal("accepted", invalid)
			}
		}
		if err := l.validate("minimum-remaining", "1m", 30*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
}
