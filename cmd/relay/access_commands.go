package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/store"
	"github.com/zksecurity/relay/internal/transcript"
)

const (
	r2ParentTokenEnvironment  = "RELAY_R2_PARENT_TOKEN"
	r2ParentSecretEnvironment = "RELAY_R2_PARENT_SECRET_ACCESS_KEY"
	r2ControlTokenEnvironment = "RELAY_R2_CONTROL_TOKEN"
)

func runConfigureStorage(args []string) error {
	set := flag.NewFlagSet("coordinator configure-storage", flag.ContinueOnError)
	var config access.StorageConfig
	var home, out string
	set.StringVar(&home, "home", "", "optional absolute ceremony home for public/ and config/ defaults")
	set.StringVar(&config.Provider, "provider", "", "r2 or aws")
	set.StringVar(&config.AccountID, "account-id", "", "Cloudflare account ID (R2)")
	set.StringVar(&config.ParentAccessKeyID, "parent-access-key-id", "", "R2 parent token access-key ID")
	set.StringVar(&config.Endpoint, "endpoint", "", "S3-compatible endpoint (required for R2)")
	set.StringVar(&config.Region, "region", "", "AWS region")
	set.StringVar(&config.PublishedBucket, "published-bucket", "", "coordinator-written published bucket")
	set.StringVar(&config.PublishedBaseURL, "published-base-url", "", "anonymous HTTPS origin for published objects")
	set.StringVar(&config.InboxBucket, "inbox-bucket", "", "private role-submission bucket")
	set.StringVar(&config.CoordinatorProfile, "profile", "default", "AWS CLI profile for coordinator storage access")
	set.StringVar(&config.IssuerProfile, "issuer-profile", "", "AWS CLI profile allowed to assume the grant role")
	set.StringVar(&config.GrantRoleARN, "grant-role-arn", "", "AWS IAM role used for scoped inbox grants")
	set.StringVar(&config.GrantRoleMaxTTL, "grant-role-max-ttl", "", "configured AWS grant role maximum session duration")
	set.StringVar(&config.CeremonyPath, "ceremony", "", "signed ceremony definition")
	set.StringVar(&config.CeremonySignature, "ceremony-signature", "", "definition signature")
	set.StringVar(&config.CoordinatorPublicKey, "coordinator-key", "", "out-of-band coordinator public key")
	set.StringVar(&config.CeremonyBinary, "ceremony-binary", "mpc-ceremony", "trusted ceremony executable")
	set.StringVar(&out, "out", "", "fresh storage configuration path")
	if err := set.Parse(args); err != nil {
		return err
	}
	if home != "" {
		if !filepath.IsAbs(home) || filepath.Clean(home) != home {
			return errors.New("--home must be an absolute clean path")
		}
		if config.CeremonyPath == "" {
			config.CeremonyPath = filepath.Join(home, "public", "ceremony.json")
		}
		if config.CeremonySignature == "" {
			config.CeremonySignature = filepath.Join(home, "public", "ceremony.sig")
		}
		if out == "" {
			out = filepath.Join(home, "config", "relay-storage.json")
		}
	}
	if out == "" {
		return errors.New("--out is required unless --home supplies its config/ default")
	}
	if config.Provider == "r2" && config.Region == "" {
		config.Region = "auto"
	}
	inspector := transcript.Inspector{
		Executable: config.CeremonyBinary, CeremonyPath: config.CeremonyPath,
		CeremonySignaturePath:    config.CeremonySignature,
		CoordinatorPublicKeyPath: config.CoordinatorPublicKey,
	}
	definition, err := inspector.Definition()
	if err != nil {
		return err
	}
	config.Schema = access.StorageConfigSchema
	config.CeremonyID = definition.CeremonyID
	if err := config.Validate(); err != nil {
		return err
	}
	if err := preflightStorage(config); err != nil {
		return err
	}
	if config.Provider == "r2" {
		if err := preflightR2GrantScope(config); err != nil {
			return err
		}
	}
	if err := writeJSONNoReplace(out, config, 0o600); err != nil {
		return err
	}
	fmt.Printf("configured %s storage for ceremony %s\n", config.Provider, config.CeremonyID)
	fmt.Printf("published: %s\ninbox:    %s\n", config.PublishedBaseURL, config.InboxBucket)
	return nil
}

func preflightStorage(config access.StorageConfig) (result error) {
	if config.Provider == "r2" {
		if err := preflightR2InboxPrivacy(config); err != nil {
			return err
		}
	}
	return checkStorageObjects(config, newScopeProbeStore, time.Sleep)
}

func checkStorageObjects(config access.StorageConfig, clientFor func(store.Client) scopeProbeStore, pause func(time.Duration)) (result error) {
	attempt, err := randomID()
	if err != nil {
		return err
	}
	key := "setup-probes/" + attempt
	if config.CeremonyID != "" {
		key = "setup-probes/" + strings.TrimPrefix(config.CeremonyID, "sha256:") + "/" + attempt
	}
	dir, err := os.MkdirTemp("", "relay-storage-probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	source := filepath.Join(dir, "probe")
	payload := []byte("relay storage preflight " + attempt + "\n")
	if err := os.WriteFile(source, payload, 0o600); err != nil {
		return err
	}
	published := clientFor(coordinatorClient(config, config.PublishedBucket))
	if err := published.PutNoReplace(key, source); err != nil {
		return probeWriteFailure(config.PublishedBucket, key, err)
	}
	publishedPending := true
	defer func() {
		if publishedPending {
			if err := published.Delete(key); err != nil {
				result = errors.Join(result, fmt.Errorf("cleanup failed: remove only published probe %s in bucket %s: %w", key, config.PublishedBucket, err))
			}
		}
	}()
	authenticated := filepath.Join(dir, "authenticated")
	if err := published.Get(key, authenticated); err != nil {
		return fmt.Errorf("published bucket authenticated read probe: %w", err)
	}
	if got, err := os.ReadFile(authenticated); err != nil || !bytes.Equal(got, payload) {
		return errors.New("authenticated published read returned different probe bytes")
	}
	public := clientFor(store.Client{PublicBaseURL: config.PublishedBaseURL})
	var publicErr error
	for attemptNumber := 0; attemptNumber < 5; attemptNumber++ {
		publicPath := filepath.Join(dir, "public-"+strconv.Itoa(attemptNumber))
		publicErr = public.Get(key, publicPath)
		if publicErr == nil {
			got, readErr := os.ReadFile(publicPath)
			if readErr != nil || !bytes.Equal(got, payload) {
				return errors.New("published base URL returned different probe bytes")
			}
			break
		}
		pause(time.Second)
	}
	if publicErr != nil {
		return fmt.Errorf("anonymous published read probe: %w", publicErr)
	}

	inbox := clientFor(coordinatorClient(config, config.InboxBucket))
	if err := inbox.PutNoReplace(key, source); err != nil {
		return probeWriteFailure(config.InboxBucket, key, err)
	}
	inboxPending := true
	defer func() {
		if inboxPending {
			if err := inbox.Delete(key); err != nil {
				result = errors.Join(result, fmt.Errorf("cleanup failed: remove only inbox probe %s in bucket %s: %w", key, config.InboxBucket, err))
			}
		}
	}()
	if config.Provider != "r2" {
		unsigned := clientFor(store.Client{Endpoint: config.Endpoint, Region: config.Region, Bucket: config.InboxBucket, NoSign: true})
		publiclyVisible, headErr := unsigned.Head(key)
		if headErr == nil && publiclyVisible {
			return errors.New("private inbox probe was anonymously readable")
		}
		if headErr == nil || !isAccessDenied(headErr) {
			return errors.New("anonymous inbox privacy probe was inconclusive: require an explicit access denial for the probe object")
		}
	}
	if err := inbox.Delete(key); err != nil {
		return fmt.Errorf("remove inbox probe: %w", err)
	}
	inboxPending = false
	if err := published.Delete(key); err != nil {
		return fmt.Errorf("remove published probe: %w", err)
	}
	publishedPending = false
	return nil
}

func isAccessDenied(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "accessdenied") || strings.Contains(message, "access denied") ||
		strings.Contains(message, "forbidden") || strings.Contains(message, "403")
}

func runGrant(args []string) error {
	set := flag.NewFlagSet("coordinator grant", flag.ContinueOnError)
	var storagePath, role, identity, ttlText, minimumText, legacyMinimumText, enrollment, enrollmentSignature, out string
	set.StringVar(&storagePath, "storage", "", "storage configuration from configure-storage")
	set.StringVar(&role, "role", "", "participant, witness, mirror, auditor, release, decision")
	set.StringVar(&identity, "identity", "", "authenticated ceremony or enrollment identity")
	set.StringVar(&ttlText, "credential-ttl", "", "required temporary credential lifetime")
	set.StringVar(&minimumText, "minimum-remaining", "", "required credential lifetime remaining before work begins")
	set.StringVar(&legacyMinimumText, "minimum-upload-window", "", "deprecated alias for --minimum-remaining")
	set.StringVar(&enrollment, "enrollment", "", "signed operational enrollment for roles other than participant")
	set.StringVar(&enrollmentSignature, "enrollment-signature", "", "detached enrollment signature")
	set.StringVar(&out, "out", "", "fresh secret grant file")
	if err := set.Parse(args); err != nil {
		return err
	}
	if minimumText != "" && legacyMinimumText != "" {
		return errors.New("pass only one of --minimum-remaining or deprecated --minimum-upload-window")
	}
	if minimumText == "" {
		minimumText = legacyMinimumText
	}
	if storagePath == "" || role == "" || identity == "" || ttlText == "" || minimumText == "" || out == "" {
		return errors.New("--storage, --role, --identity, --credential-ttl, --minimum-remaining and --out are required")
	}
	config, err := loadStorageConfig(storagePath)
	if err != nil {
		return err
	}
	ttl, err := time.ParseDuration(ttlText)
	if err != nil || ttl < time.Second || ttl%time.Second != 0 {
		return errors.New("--credential-ttl must be a positive whole-second duration")
	}
	minimum, err := time.ParseDuration(minimumText)
	if err != nil || minimum <= 0 || minimum > ttl {
		return errors.New("--minimum-remaining must be positive and no greater than --credential-ttl")
	}
	prefix, err := access.Prefix(config.CeremonyID, role, identity)
	if err != nil {
		return err
	}
	if err := authenticateGrantIdentity(config, role, identity, enrollment, enrollmentSignature); err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	credentials, expires, err := issueCredentials(config, identity, prefix, ttl, now)
	if err != nil {
		return err
	}
	grant := access.Grant{
		Schema: access.GrantSchema, Provider: config.Provider, CeremonyID: config.CeremonyID,
		Role: role, IdentityID: identity, Endpoint: config.Endpoint, Region: config.Region,
		InboxBucket: config.InboxBucket, Prefix: prefix,
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: expires.UTC().Format(time.RFC3339),
		MinimumRemaining: minimum.String(), Credentials: credentials,
	}
	if err := grant.Validate(); err != nil {
		return err
	}
	if err := writeJSONNoReplace(out, grant, 0o600); err != nil {
		return err
	}
	fmt.Printf("issued %s grant for %s\nprefix:  %s\nexpires: %s\n", role, identity, prefix, grant.ExpiresAt)
	return nil
}

func authenticateGrantIdentity(config access.StorageConfig, role, identity, enrollment, enrollmentSignature string) error {
	inspector := transcript.Inspector{
		Executable: config.CeremonyBinary, CeremonyPath: config.CeremonyPath,
		CeremonySignaturePath:    config.CeremonySignature,
		CoordinatorPublicKeyPath: config.CoordinatorPublicKey,
	}
	if role == access.RoleParticipant {
		definition, err := inspector.Definition()
		if err != nil {
			return err
		}
		if definition.CeremonyID != config.CeremonyID {
			return errors.New("authenticated definition does not match the storage ceremony")
		}
		for _, participant := range append(append([]string(nil), definition.Phase1Participants...), definition.Phase2Participants...) {
			if participant == identity {
				return nil
			}
		}
		return fmt.Errorf("participant %q is not scheduled in the authenticated definition", identity)
	}
	if enrollment == "" || enrollmentSignature == "" {
		return errors.New("--enrollment and --enrollment-signature are required for non-participant grants")
	}
	inspection, err := inspector.Enrollment(enrollment, enrollmentSignature)
	if err != nil {
		return err
	}
	if inspection.CeremonyID != config.CeremonyID || inspection.Identity.ID != identity {
		return errors.New("enrollment does not match the configured ceremony and requested identity")
	}
	if role == access.RoleDecision {
		if inspection.Role != "coordinator" && inspection.Role != "auditor" && inspection.Role != "release-signer" {
			return fmt.Errorf("enrollment role %q cannot sign a production decision", inspection.Role)
		}
		return nil
	}
	if expected, ok := ceremonyEnrollmentRole(role); !ok || inspection.Role != expected {
		return fmt.Errorf("enrollment role %q does not authorize relay role %q", inspection.Role, role)
	}
	return nil
}

func issueCredentials(config access.StorageConfig, identity, prefix string, ttl time.Duration, now time.Time) (access.SessionCredentials, time.Time, error) {
	if config.Provider == "r2" {
		return issueR2(config, prefix, ttl, now)
	}
	return issueAWS(config, identity, prefix, ttl)
}

func issueR2(config access.StorageConfig, prefix string, ttl time.Duration, now time.Time) (access.SessionCredentials, time.Time, error) {
	if ttl > 168*time.Hour {
		return access.SessionCredentials{}, time.Time{}, errors.New("R2 --credential-ttl must not exceed 168h")
	}
	secret, err := consumeR2Credential(r2ParentSecretEnvironment)
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	if secret != "" {
		if err := os.Unsetenv(r2ParentSecretEnvironment); err != nil {
			return access.SessionCredentials{}, time.Time{}, fmt.Errorf("clear %s before issuing credentials: %w", r2ParentSecretEnvironment, err)
		}
		return issueR2Locally(config, prefix, ttl, now, secret)
	}
	token, err := consumeR2Credential(r2ParentTokenEnvironment)
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	if token == "" {
		return access.SessionCredentials{}, time.Time{}, fmt.Errorf("%s or %s is required", r2ParentSecretEnvironment, r2ParentTokenEnvironment)
	}
	if err := os.Unsetenv(r2ParentTokenEnvironment); err != nil {
		return access.SessionCredentials{}, time.Time{}, fmt.Errorf("clear %s before issuing credentials: %w", r2ParentTokenEnvironment, err)
	}
	body, err := json.Marshal(map[string]any{
		"bucket": config.InboxBucket, "parentAccessKeyId": config.ParentAccessKeyID,
		"permission": "object-read-write", "ttlSeconds": int64(ttl / time.Second),
		"prefixes": []string{prefix},
	})
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	endpoint := "https://api.cloudflare.com/client/v4/accounts/" + config.AccountID + "/r2/temp-access-credentials"
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	var decoded struct {
		Success bool `json:"success"`
		Result  struct {
			AccessKeyID     string `json:"accessKeyId"`
			SecretAccessKey string `json:"secretAccessKey"`
			SessionToken    string `json:"sessionToken"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return access.SessionCredentials{}, time.Time{}, fmt.Errorf("decode R2 temporary credentials: %w", err)
	}
	if response.StatusCode != http.StatusOK || !decoded.Success {
		message := response.Status
		if len(decoded.Errors) > 0 && decoded.Errors[0].Message != "" {
			message = decoded.Errors[0].Message
		}
		return access.SessionCredentials{}, time.Time{}, fmt.Errorf("R2 temporary credentials: %s", message)
	}
	credentials := access.SessionCredentials{
		AccessKeyID: decoded.Result.AccessKeyID, SecretAccessKey: decoded.Result.SecretAccessKey,
		SessionToken: decoded.Result.SessionToken,
	}
	return credentials, now.Add(ttl), credentials.Validate()
}

func issueR2Locally(config access.StorageConfig, prefix string, ttl time.Duration, now time.Time, secret string) (access.SessionCredentials, time.Time, error) {
	decodedSecret, err := hex.DecodeString(secret)
	if err != nil || len(decodedSecret) != sha256.Size || secret != strings.ToLower(secret) {
		return access.SessionCredentials{}, time.Time{}, fmt.Errorf("%s must be 64 lowercase hexadecimal characters", r2ParentSecretEnvironment)
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return access.SessionCredentials{}, time.Time{}, errors.New("R2 endpoint must be an HTTPS origin")
	}
	expires := now.Add(ttl)
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}{Algorithm: "HS256", Type: "JWT"})
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	type r2Paths struct {
		PrefixPaths []string `json:"prefixPaths"`
		ObjectPaths []string `json:"objectPaths"`
	}
	claims, err := json.Marshal(struct {
		Bucket    string  `json:"bucket"`
		Scope     string  `json:"scope"`
		Paths     r2Paths `json:"paths"`
		Subject   string  `json:"sub"`
		Issuer    string  `json:"iss"`
		Audience  string  `json:"aud"`
		IssuedAt  int64   `json:"iat"`
		ExpiresAt int64   `json:"exp"`
	}{
		Bucket: config.InboxBucket, Scope: "object-read-write",
		Paths:   r2Paths{PrefixPaths: []string{prefix}, ObjectPaths: []string{}},
		Subject: config.AccountID, Issuer: config.ParentAccessKeyID,
		Audience: endpoint.Host, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(),
	})
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	unsigned := encodedHeader + "." + encodedClaims
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(unsigned))
	jws := unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	temporarySecret := sha256.Sum256([]byte(jws))
	credentials := access.SessionCredentials{
		AccessKeyID:     config.ParentAccessKeyID,
		SecretAccessKey: hex.EncodeToString(temporarySecret[:]),
		SessionToken:    base64.StdEncoding.EncodeToString([]byte("jwt/" + jws)),
	}
	return credentials, expires, credentials.Validate()
}

func issueAWS(config access.StorageConfig, identity, prefix string, ttl time.Duration) (access.SessionCredentials, time.Time, error) {
	return issueAWSWithRunner(config, identity, prefix, ttl, func(args ...string) ([]byte, error) {
		command := exec.Command("aws", args...)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			return nil, fmt.Errorf("AWS STS assume-role: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return stdout.Bytes(), nil
	})
}

func issueAWSWithRunner(config access.StorageConfig, identity, prefix string, ttl time.Duration, run func(...string) ([]byte, error)) (access.SessionCredentials, time.Time, error) {
	maximum, _ := time.ParseDuration(config.GrantRoleMaxTTL)
	if ttl < 15*time.Minute || ttl > maximum {
		return access.SessionCredentials{}, time.Time{}, fmt.Errorf("AWS --credential-ttl must be between 15m and %s", maximum)
	}
	objectARN := "arn:aws:s3:::" + config.InboxBucket + "/" + prefix + "*"
	policy, err := json.Marshal(map[string]any{
		"Version": "2012-10-17",
		"Statement": []map[string]any{{
			"Effect":   "Allow",
			"Action":   []string{"s3:PutObject", "s3:GetObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"},
			"Resource": objectARN,
		}},
	})
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	session := "relay-" + strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, identity)
	if len(session) > 64 {
		session = session[:64]
	}
	raw, err := run("--profile", config.IssuerProfile, "--region", config.Region,
		"sts", "assume-role", "--role-arn", config.GrantRoleARN,
		"--role-session-name", session, "--duration-seconds", strconv.FormatInt(int64(ttl/time.Second), 10),
		"--policy", string(policy), "--output", "json")
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, err
	}
	var result struct {
		Credentials struct {
			AccessKeyID     string `json:"AccessKeyId"`
			SecretAccessKey string `json:"SecretAccessKey"`
			SessionToken    string `json:"SessionToken"`
			Expiration      string `json:"Expiration"`
		} `json:"Credentials"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return access.SessionCredentials{}, time.Time{}, fmt.Errorf("decode AWS STS credentials: %w", err)
	}
	expires, err := time.Parse(time.RFC3339, result.Credentials.Expiration)
	if err != nil {
		return access.SessionCredentials{}, time.Time{}, errors.New("AWS STS returned an invalid expiration")
	}
	credentials := access.SessionCredentials{AccessKeyID: result.Credentials.AccessKeyID,
		SecretAccessKey: result.Credentials.SecretAccessKey, SessionToken: result.Credentials.SessionToken}
	return credentials, expires, credentials.Validate()
}

func coordinatorClient(config access.StorageConfig, bucket string) store.Client {
	return store.Client{Profile: config.CoordinatorProfile, Endpoint: config.Endpoint, Region: config.Region, Bucket: bucket}
}

func grantClient(grant access.Grant) store.Client {
	credentials := store.Credentials{AccessKeyID: grant.Credentials.AccessKeyID,
		SecretAccessKey: grant.Credentials.SecretAccessKey, SessionToken: grant.Credentials.SessionToken}
	return store.Client{Endpoint: grant.Endpoint, Region: grant.Region, Bucket: grant.InboxBucket, Credentials: &credentials}
}

func loadStorageConfig(path string) (access.StorageConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return access.StorageConfig{}, err
	}
	return access.Decode(raw, access.StorageConfig.Validate)
}

func loadGrant(path string) (access.Grant, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return access.Grant{}, err
	}
	return access.Decode(raw, access.Grant.Validate)
}

func writeJSONNoReplace(path string, value any, mode os.FileMode) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	return file.Close()
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
