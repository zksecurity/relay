package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/store"
)

func TestR2ScopeProbesRejectExcessAccessAndCleanConfirmedWrites(t *testing.T) {
	for _, fault := range []string{"", "parent-overprivileged", "grant-overprivileged", "expired-usable", "allowed-denied", "cleanup-failed", "uncertain-write"} {
		t.Run(fault, func(t *testing.T) {
			c := access.StorageConfig{Provider: "r2", AccountID: strings.Repeat("a", 32), ParentAccessKeyID: strings.Repeat("b", 32), Endpoint: "https://account.r2.cloudflarestorage.com", InboxBucket: "inbox", PublishedBucket: "published", CoordinatorProfile: "coordinator"}
			objects := map[string][]byte{}
			factory := func(client store.Client) scopeProbeStore {
				allow := func(key string) bool {
					if client.Credentials == nil {
						return true
					}
					if client.Credentials.SessionToken == "" {
						return fault == "parent-overprivileged"
					}
					raw, err := base64.StdEncoding.DecodeString(client.Credentials.SessionToken)
					if err != nil {
						t.Fatal(err)
					}
					parts := strings.Split(strings.TrimPrefix(string(raw), "jwt/"), ".")
					if len(parts) != 3 {
						t.Fatal("invalid local JWT")
					}
					payload, err := base64.RawURLEncoding.DecodeString(parts[1])
					if err != nil {
						t.Fatal(err)
					}
					var claims struct {
						Exp int64 `json:"exp"`
					}
					if err := json.Unmarshal(payload, &claims); err != nil {
						t.Fatal(err)
					}
					if claims.Exp < time.Now().Unix() {
						return fault == "expired-usable"
					}
					if fault == "grant-overprivileged" {
						return true
					}
					return fault != "allowed-denied" && client.Bucket == c.InboxBucket && strings.Contains(key, "/allowed/")
				}
				return scopeProbeStore{Bucket: client.Bucket,
					PutNoReplace: func(key, path string) error {
						if !allow(key) {
							return errors.New("AccessDenied")
						}
						if !strings.HasPrefix(key, "setup-probes/") {
							t.Fatal("probe escaped its namespace")
						}
						id := client.Bucket + "/" + key
						if _, exists := objects[id]; exists {
							return store.ErrExists
						}
						raw, err := os.ReadFile(path)
						if err != nil {
							return err
						}
						objects[id] = raw
						if fault == "uncertain-write" {
							return errors.New("connection lost after storage accepted write")
						}
						return nil
					},
					Get: func(key, path string) error {
						if !allow(key) {
							return errors.New("AccessDenied")
						}
						raw, exists := objects[client.Bucket+"/"+key]
						if !exists {
							return errors.New("NoSuchKey")
						}
						return os.WriteFile(path, raw, 0600)
					},
					Delete: func(key string) error {
						if fault == "cleanup-failed" {
							return errors.New("AccessDenied")
						}
						delete(objects, client.Bucket+"/"+key)
						return nil
					},
				}
			}
			err := checkR2GrantScope(c, strings.Repeat("c", 64), factory)
			if (err == nil) != (fault == "") {
				t.Fatalf("fault %q: %v", fault, err)
			}
			if fault == "uncertain-write" {
				if err == nil || !strings.Contains(err.Error(), "setup-probes/") || !strings.Contains(err.Error(), "lost response") {
					t.Fatal("uncertain write lacks recovery location")
				}
			} else if fault == "cleanup-failed" {
				if err == nil || !strings.Contains(err.Error(), "cleanup failed") {
					t.Fatal("cleanup failure not reported")
				}
			} else if len(objects) != 0 {
				t.Fatalf("left %d confirmed probe objects behind", len(objects))
			}
		})
	}
}

func TestProbeCollisionIsNotReportedAsErased(t *testing.T) {
	err := probeWriteFailure("bucket", "setup-probes/collision", store.ErrExists)
	if !strings.Contains(err.Error(), "not replaced or deleted") {
		t.Fatal(err)
	}
}
