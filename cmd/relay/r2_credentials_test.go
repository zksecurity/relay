package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

func TestIssueR2LocallyProducesScopedCredential(t *testing.T) {
	t.Parallel()
	config := access.StorageConfig{
		Endpoint:          "https://account-id.r2.cloudflarestorage.com",
		AccountID:         strings.Repeat("a", 32),
		ParentAccessKeyID: strings.Repeat("b", 32),
		InboxBucket:       "private-inbox",
	}
	prefix := "candidates/ceremony/participant/"
	secret := strings.Repeat("c", 64)
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	credentials, expires, err := issueR2Locally(config, prefix, 2*time.Hour, now, secret)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.AccessKeyID != config.ParentAccessKeyID {
		t.Fatalf("access key = %q", credentials.AccessKeyID)
	}
	if !expires.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("expiration = %s", expires)
	}
	session, err := base64.StdEncoding.DecodeString(credentials.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	encodedJWT := strings.TrimPrefix(string(session), "jwt/")
	if encodedJWT == string(session) {
		t.Fatal("session token lacks jwt/ marker")
	}
	parts := strings.Split(encodedJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d components", len(parts))
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		t.Fatal("JWT signature is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Bucket string `json:"bucket"`
		Scope  string `json:"scope"`
		Paths  struct {
			PrefixPaths []string `json:"prefixPaths"`
			ObjectPaths []string `json:"objectPaths"`
		} `json:"paths"`
		Subject   string `json:"sub"`
		Issuer    string `json:"iss"`
		Audience  string `json:"aud"`
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Bucket != config.InboxBucket || claims.Scope != "object-read-write" ||
		claims.Subject != config.AccountID || claims.Issuer != config.ParentAccessKeyID ||
		claims.Audience != "account-id.r2.cloudflarestorage.com" ||
		claims.IssuedAt != now.Unix() || claims.ExpiresAt != expires.Unix() {
		t.Fatalf("unexpected JWT claims: %+v", claims)
	}
	if len(claims.Paths.PrefixPaths) != 1 || claims.Paths.PrefixPaths[0] != prefix ||
		len(claims.Paths.ObjectPaths) != 0 {
		t.Fatalf("unexpected JWT paths: %+v", claims.Paths)
	}
	wantSecret := sha256.Sum256([]byte(encodedJWT))
	if credentials.SecretAccessKey != hex.EncodeToString(wantSecret[:]) {
		t.Fatal("temporary secret does not match JWT digest")
	}
}

func TestIssueR2PrefersAndClearsLocalSecret(t *testing.T) {
	config := access.StorageConfig{
		Endpoint:          "https://account-id.r2.cloudflarestorage.com",
		AccountID:         strings.Repeat("a", 32),
		ParentAccessKeyID: strings.Repeat("b", 32),
		InboxBucket:       "private-inbox",
	}
	t.Setenv(r2ParentSecretEnvironment, strings.Repeat("c", 64))
	t.Setenv(r2ParentTokenEnvironment, "hosted-endpoint-must-not-be-used")
	if _, _, err := issueR2(config, "prefix/", time.Hour, time.Unix(0, 0).UTC()); err != nil {
		t.Fatal(err)
	}
	if _, exists := os.LookupEnv(r2ParentSecretEnvironment); exists {
		t.Fatalf("%s was not cleared", r2ParentSecretEnvironment)
	}
}

func TestIssueR2LocallyRejectsMalformedSecret(t *testing.T) {
	config := access.StorageConfig{
		Endpoint:          "https://account-id.r2.cloudflarestorage.com",
		AccountID:         strings.Repeat("a", 32),
		ParentAccessKeyID: strings.Repeat("b", 32),
		InboxBucket:       "private-inbox",
	}
	if _, _, err := issueR2Locally(config, "prefix/", time.Hour, time.Unix(0, 0).UTC(), "not-a-secret"); err == nil {
		t.Fatal("malformed secret was accepted")
	}
}
