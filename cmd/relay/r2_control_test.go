package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zksecurity/relay/internal/access"
)

func TestCheckR2InboxPrivacyAcceptsPrivateBucket(t *testing.T) {
	server := r2PrivacyServer(t,
		`{"success":true,"result":{"bucketId":"bucket-id","domain":"pub-private.r2.dev","enabled":false},"errors":[]}`,
		`{"success":true,"result":{"domains":[]},"errors":[]}`,
	)
	defer server.Close()

	if err := checkR2InboxPrivacy(r2PrivacyConfig(), "control-token", server.Client(), server.URL); err != nil {
		t.Fatal(err)
	}
}

func TestCheckR2InboxPrivacyRejectsPublicR2Dev(t *testing.T) {
	server := r2PrivacyServer(t,
		`{"success":true,"result":{"bucketId":"bucket-id","domain":"pub-inbox.r2.dev","enabled":true},"errors":[]}`,
		`{"success":true,"result":{"domains":[]},"errors":[]}`,
	)
	defer server.Close()

	err := checkR2InboxPrivacy(r2PrivacyConfig(), "control-token", server.Client(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "public r2.dev access enabled") {
		t.Fatalf("public r2.dev error = %v", err)
	}
}

func TestCheckR2InboxPrivacyRejectsAttachedCustomDomain(t *testing.T) {
	server := r2PrivacyServer(t,
		`{"success":true,"result":{"bucketId":"bucket-id","domain":"pub-private.r2.dev","enabled":false},"errors":[]}`,
		`{"success":true,"result":{"domains":[{"domain":"inbox.example.com","enabled":false}]},"errors":[]}`,
	)
	defer server.Close()

	err := checkR2InboxPrivacy(r2PrivacyConfig(), "control-token", server.Client(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "custom domains attached: inbox.example.com") {
		t.Fatalf("custom domain error = %v", err)
	}
}

func TestCheckR2InboxPrivacyReportsControlAPIFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"success":false,"result":null,"errors":[{"message":"permission denied"}]}`)
	}))
	defer server.Close()

	err := checkR2InboxPrivacy(r2PrivacyConfig(), "control-token", server.Client(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("control API error = %v", err)
	}
}

func TestCheckR2InboxPrivacyRejectsIncompleteControlAPIResponse(t *testing.T) {
	server := r2PrivacyServer(t,
		`{"success":true,"result":{"bucketId":"bucket-id","domain":"pub-private.r2.dev"},"errors":[]}`,
		`{"success":true,"result":{"domains":[]},"errors":[]}`,
	)
	defer server.Close()

	err := checkR2InboxPrivacy(r2PrivacyConfig(), "control-token", server.Client(), server.URL)
	if err == nil || !strings.Contains(err.Error(), "omitted required fields") {
		t.Fatalf("incomplete control API error = %v", err)
	}
}

func TestPreflightR2InboxPrivacyRequiresControlToken(t *testing.T) {
	t.Setenv(r2ControlTokenEnvironment, "")
	err := preflightR2InboxPrivacy(r2PrivacyConfig())
	if err == nil || !strings.Contains(err.Error(), r2ControlTokenEnvironment+" is required") {
		t.Fatalf("missing token error = %v", err)
	}
}

func r2PrivacyConfig() access.StorageConfig {
	return access.StorageConfig{AccountID: "account-id", InboxBucket: "private-inbox"}
}

func r2PrivacyServer(t *testing.T, managed, custom string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer control-token" {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/accounts/account-id/r2/buckets/private-inbox/domains/managed":
			fmt.Fprint(w, managed)
		case "/accounts/account-id/r2/buckets/private-inbox/domains/custom":
			fmt.Fprint(w, custom)
		default:
			http.NotFound(w, request)
		}
	}))
}
