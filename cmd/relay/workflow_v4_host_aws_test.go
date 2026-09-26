package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zksecurity/relay/internal/access"
)

func TestBoundHostAWSUsesVerifiedSourceLoginWithoutHostAlias(t *testing.T) {
	binding := fakeAWSLogin(t)
	path := filepath.Join(t.TempDir(), "aws-login.json")
	if err := saveJSONAtomic(path, binding); err != nil {
		t.Fatal(err)
	}
	online := guidedProfile{Credentials: path}
	config := access.StorageConfig{Region: "us-east-1", CoordinatorProfile: "relay-coordinator"}
	client, err := workflowV4BoundHostAWS(online, config, "published")
	if err != nil {
		t.Fatal(err)
	}
	if client.Profile != "" || client.Binary != binding.Binary || client.CredentialProvider == nil {
		t.Fatal("host publication still depends on a relay-coordinator host alias")
	}
	credentials, err := client.CredentialProvider(context.Background())
	if err != nil || credentials.AccessKeyID != "TESTACCESS" || credentials.SessionToken == "" {
		t.Fatalf("verified login was not used: %v", err)
	}
	config.Region = "eu-west-1"
	if _, err := workflowV4BoundHostAWS(online, config, "published"); err == nil {
		t.Fatal("accepted a login for another region")
	}
}

func TestBoundHostAWSUsesIsolatedLegacyCredentialFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials")
	if err := os.WriteFile(path, []byte("[relay-coordinator]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := workflowV4BoundHostAWS(guidedProfile{Credentials: path}, access.StorageConfig{Region: "us-east-1", CoordinatorProfile: "relay-coordinator"}, "published")
	if err != nil || client.CredentialsFile != path || client.Profile != "relay-coordinator" || client.CredentialProvider != nil {
		t.Fatalf("legacy credentials were not isolated: %v", err)
	}
}
