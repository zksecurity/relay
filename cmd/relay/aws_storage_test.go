package main

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/store"
)

func TestAWSGrantRequestsOnlyIntendedInboxPrefix(t *testing.T) {
	config, err := storageSettingsFixture().infrastructure()
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Second)
	for _, ttl := range []time.Duration{14 * time.Minute, 15 * time.Minute, 2 * time.Hour} {
		called := false
		_, gotExpires, err := issueAWSWithRunner(config, "participant-01", "setup-probes/test/allowed/", ttl, func(args ...string) ([]byte, error) {
			called = true
			value := func(flag string) string {
				for i, a := range args {
					if a == flag && i+1 < len(args) {
						return args[i+1]
					}
				}
				return ""
			}
			if value("--profile") != config.IssuerProfile || value("--role-arn") != config.GrantRoleARN || value("--duration-seconds") != "900" {
				t.Fatal("wrong STS request")
			}
			var policy struct {
				Statement []struct {
					Effect   string
					Resource string
					Action   []string
				}
			}
			if err := json.Unmarshal([]byte(value("--policy")), &policy); err != nil {
				t.Fatal(err)
			}
			if len(policy.Statement) != 1 || policy.Statement[0].Effect != "Allow" || policy.Statement[0].Resource != "arn:aws:s3:::private-fixture/setup-probes/test/allowed/*" {
				t.Fatal("session policy escaped intended prefix")
			}
			if strings.Join(policy.Statement[0].Action, ",") != "s3:PutObject,s3:GetObject,s3:AbortMultipartUpload,s3:ListMultipartUploadParts" {
				t.Fatal("unexpected session permissions")
			}
			return json.Marshal(map[string]any{"Credentials": map[string]string{"AccessKeyId": "test-access", "SecretAccessKey": "test-secret", "SessionToken": "test-session", "Expiration": expires.Format(time.RFC3339)}})
		})
		if ttl == 15*time.Minute {
			if err != nil || !called || !gotExpires.Equal(expires) {
				t.Fatalf("valid request: %v", err)
			}
		} else if err == nil || called {
			t.Fatal("invalid TTL reached STS")
		}
	}
}

func TestAWSStoragePreflightAndFailureCleanup(t *testing.T) {
	for _, fault := range []string{"", "public-inbox", "inbox-not-found", "inbox-network-error", "authenticated-corruption", "public-corruption", "public-unavailable", "inbox-write-denied", "delete-denied", "ambiguous-write", "collision"} {
		t.Run(fault, func(t *testing.T) {
			config, err := storageSettingsFixture().infrastructure()
			if err != nil {
				t.Fatal(err)
			}
			objects := map[string][]byte{}
			factory := func(c store.Client) scopeProbeStore {
				bucket := c.Bucket
				if c.PublicBaseURL != "" {
					bucket = config.PublishedBucket
				}
				return scopeProbeStore{Bucket: bucket,
					PutNoReplace: func(key, file string) error {
						if !strings.HasPrefix(key, "setup-probes/") || strings.Contains(key, "//") {
							t.Fatal("invalid probe namespace", key)
						}
						if fault == "collision" {
							return store.ErrExists
						}
						if fault == "inbox-write-denied" && bucket == config.InboxBucket {
							return errors.New("AccessDenied")
						}
						raw, err := os.ReadFile(file)
						if err != nil {
							return err
						}
						objects[bucket+"/"+key] = raw
						if fault == "ambiguous-write" {
							return errors.New("lost response")
						}
						return nil
					},
					Get: func(key, file string) error {
						if fault == "public-unavailable" && c.PublicBaseURL != "" {
							return errors.New("connection failed")
						}
						raw, ok := objects[bucket+"/"+key]
						if !ok {
							return errors.New("NoSuchKey")
						}
						if (fault == "authenticated-corruption" && c.PublicBaseURL == "") || (fault == "public-corruption" && c.PublicBaseURL != "") {
							raw = []byte("different bytes")
						}
						return os.WriteFile(file, raw, 0600)
					},
					Head: func(key string) (bool, error) {
						if !c.NoSign || bucket != config.InboxBucket {
							t.Fatal("privacy check not anonymous or wrong bucket")
						}
						if _, ok := objects[bucket+"/"+key]; !ok {
							t.Fatal("privacy check did not target the newly written object")
						}
						switch fault {
						case "public-inbox":
							return true, nil
						case "inbox-not-found":
							return false, nil
						case "inbox-network-error":
							return false, errors.New("connection failed")
						default:
							return false, errors.New("AccessDenied")
						}
					},
					Delete: func(key string) error {
						if fault == "delete-denied" {
							return errors.New("AccessDenied")
						}
						delete(objects, bucket+"/"+key)
						return nil
					},
				}
			}
			err = checkStorageObjects(config, factory, func(time.Duration) {})
			if (err == nil) != (fault == "") {
				t.Fatalf("fault %q: %v", fault, err)
			}
			if fault == "delete-denied" || fault == "ambiguous-write" {
				if err == nil || !strings.Contains(err.Error(), "setup-probes/") {
					t.Fatal("missing recovery location", err)
				}
			} else if len(objects) != 0 {
				t.Fatalf("left %d confirmed writes behind", len(objects))
			}
		})
	}
}
