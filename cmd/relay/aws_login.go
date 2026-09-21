package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/zksecurity/relay/internal/access"
)

const awsLoginSchema = "relay-aws-login-v1"
const awsLoginReserve = 3 * time.Minute

type awsLoginBinding struct {
	Schema      string           `json:"schema"`
	Binary      string           `json:"binary"`
	SHA256      string           `json:"sha256"`
	Profile     string           `json:"profile"`
	Region      string           `json:"region"`
	Config      string           `json:"config"`
	Credentials string           `json:"credentials"`
	Cache       string           `json:"cache"`
	Identity    awsLoginIdentity `json:"identity"`
}
type awsLoginIdentity struct{ Account, Arn, UserId string }
type awsProcessCredentials struct {
	Version         int
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string `json:",omitempty"`
	Expiration      string `json:",omitempty"`
}

var errAWSLoginInvalid = errors.New("AWS login returned invalid credentials or a different identity; rebind the intended login")

func parseAWSProcess(raw []byte, now time.Time, reserve time.Duration) (awsProcessCredentials, error) {
	if len(raw) > 64*1024 {
		return awsProcessCredentials{}, errAWSLoginInvalid
	}
	c, err := access.Decode(raw, func(c awsProcessCredentials) error {
		valid := regexp.MustCompile(`^[A-Za-z0-9/+=]+$`)
		if c.Version != 1 || !valid.MatchString(c.AccessKeyId) || !valid.MatchString(c.SecretAccessKey) || (c.SessionToken != "" && !valid.MatchString(c.SessionToken)) {
			return errAWSLoginInvalid
		}
		if c.Expiration == "" {
			if c.SessionToken != "" {
				return errAWSLoginInvalid
			}
			return nil
		}
		expiry, e := time.Parse(time.RFC3339, c.Expiration)
		if e != nil || !expiry.After(now.Add(reserve)) {
			return errAWSLoginInvalid
		}
		return nil
	})
	if err != nil {
		return awsProcessCredentials{}, errAWSLoginInvalid
	}
	return c, nil
}

func normalizedAWSIdentity(i awsLoginIdentity) (awsLoginIdentity, error) {
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(i.Account) || !regexp.MustCompile(`^[A-Za-z0-9]+(:[A-Za-z0-9+=,.@_-]+)?$`).MatchString(i.UserId) {
		return i, errAWSLoginInvalid
	}
	prefix := "arn:aws:"
	if !strings.HasPrefix(i.Arn, prefix) || !strings.Contains(i.Arn, "::"+i.Account+":") {
		return i, errAWSLoginInvalid
	}
	if strings.HasPrefix(i.Arn, "arn:aws:sts::"+i.Account+":assumed-role/") {
		n := strings.LastIndex(i.Arn, "/")
		if n <= strings.Index(i.Arn, ":assumed-role/")+len(":assumed-role") {
			return i, errAWSLoginInvalid
		}
		i.Arn = i.Arn[:n]
		i.UserId, _, _ = strings.Cut(i.UserId, ":")
	} else if !strings.HasPrefix(i.Arn, "arn:aws:iam::"+i.Account+":user/") && !strings.HasPrefix(i.Arn, "arn:aws:iam::"+i.Account+":role/") {
		return i, errAWSLoginInvalid
	}
	return i, nil
}

func awsBinaryDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return "", errors.New("AWS CLI must be a regular executable not writable by other users")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func newAWSLoginBinding(profile, region string, identity awsLoginIdentity) (awsLoginBinding, error) {
	b := awsLoginBinding{Schema: awsLoginSchema, Profile: profile, Region: region}
	var err error
	b.Identity, err = normalizedAWSIdentity(identity)
	if err != nil {
		return b, err
	}
	b.Binary, err = exec.LookPath("aws")
	if err != nil {
		return b, err
	}
	b.Binary, err = filepath.EvalSymlinks(b.Binary)
	if err != nil {
		return b, err
	}
	b.Binary, err = filepath.Abs(b.Binary)
	if err != nil {
		return b, err
	}
	b.SHA256, err = awsBinaryDigest(b.Binary)
	if err != nil {
		return b, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return b, err
	}
	for _, field := range []struct {
		key, def string
		dst      *string
	}{
		{"AWS_CONFIG_FILE", filepath.Join(home, ".aws", "config"), &b.Config},
		{"AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, ".aws", "credentials"), &b.Credentials},
		{"AWS_LOGIN_CACHE_DIRECTORY", filepath.Join(home, ".aws", "login", "cache"), &b.Cache},
	} {
		value := os.Getenv(field.key)
		if value == "" {
			value = field.def
		}
		*field.dst, err = filepath.Abs(value)
		if err != nil {
			return b, err
		}
	}
	return b, nil
}

// A JSON credential reference is never treated as static INI, including an
// invalid or future descriptor. Validation does not execute the host login.
func readAWSLoginBinding(path string) (*awsLoginBinding, error) {
	if path == "" {
		return nil, nil
	}
	if err := validateRoleMount(path, true); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 1024*1024+1))
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return nil, nil
	}
	var b awsLoginBinding
	if len(raw) > 1024*1024 || setupReadJSON(path, &b) != nil || b.Schema != awsLoginSchema {
		return nil, errors.New("invalid AWS login binding")
	}
	for _, p := range []string{b.Binary, b.Config, b.Credentials, b.Cache} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\n\r") {
			return nil, errors.New("invalid AWS login source path")
		}
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(b.SHA256) || !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(b.Profile) || !regexp.MustCompile(`^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$`).MatchString(b.Region) {
		return nil, errors.New("invalid AWS login binding fields")
	}
	// Stored identity is already normalized; role ARNs therefore lack a session suffix.
	if b.Identity.Account == "" || b.Identity.Arn == "" || b.Identity.UserId == "" {
		return nil, errAWSLoginInvalid
	}
	return &b, nil
}

func awsLoginEnvironment(b awsLoginBinding, captured *awsProcessCredentials) []string {
	var env []string
	for _, entry := range awsSetupEnvironment() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(key, "AWS_") {
			env = append(env, entry)
		}
	}
	env = append(env, "AWS_PAGER=", "AWS_CLI_AUTO_PROMPT=off", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true", "AWS_EC2_METADATA_DISABLED=true", "AWS_DEFAULT_REGION="+b.Region)
	if captured == nil {
		return append(env, "AWS_CONFIG_FILE="+b.Config, "AWS_SHARED_CREDENTIALS_FILE="+b.Credentials, "AWS_LOGIN_CACHE_DIRECTORY="+b.Cache)
	}
	return append(env, "AWS_CONFIG_FILE=/nonexistent", "AWS_SHARED_CREDENTIALS_FILE=/nonexistent", "AWS_ACCESS_KEY_ID="+captured.AccessKeyId, "AWS_SECRET_ACCESS_KEY="+captured.SecretAccessKey, "AWS_SESSION_TOKEN="+captured.SessionToken)
}

func awsLoginCommand(ctx context.Context, b awsLoginBinding, c *awsProcessCredentials, args ...string) ([]byte, error) {
	digest, err := awsBinaryDigest(b.Binary)
	if err != nil || digest != b.SHA256 {
		return nil, errors.New("AWS CLI changed; repeat AWS setup to review and rebind it")
	}
	cmd := exec.CommandContext(ctx, b.Binary, args...)
	cmd.Env = awsLoginEnvironment(b, c)
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	var output awsSetupBuffer
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return nil, errors.New("AWS login refresh failed; check the host login and connectivity")
	}
	return output.data.Bytes(), nil
}
func refreshAWSLogin(ctx context.Context, b awsLoginBinding) (awsProcessCredentials, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	raw, err := awsLoginCommand(ctx, b, nil, "configure", "export-credentials", "--profile", b.Profile, "--format", "process")
	if err != nil {
		return awsProcessCredentials{}, err
	}
	c, err := parseAWSProcess(raw, time.Now(), awsLoginReserve)
	if err != nil {
		return c, err
	}
	if c.Expiration == "" || c.SessionToken == "" {
		return c, errAWSLoginInvalid
	}
	raw, err = awsLoginCommand(ctx, b, &c, "sts", "get-caller-identity", "--output", "json")
	if err != nil {
		return c, err
	}
	var identity awsLoginIdentity
	if json.Unmarshal(raw, &identity) != nil {
		return c, errAWSLoginInvalid
	}
	identity, err = normalizedAWSIdentity(identity)
	if err != nil || identity != b.Identity {
		return c, errAWSLoginInvalid
	}
	return c, nil
}

func runAWSLoginCredentials(args []string) error {
	if len(args) == 1 && args[0] == "--probe" {
		fmt.Fprintln(os.Stdout, awsLoginSchema)
		return nil
	}
	if len(args) != 1 || args[0] != "/credentials/aws-login/current.json" {
		return errors.New("invalid AWS credential-process invocation")
	}
	f, err := os.Open(args[0])
	if err != nil {
		return errors.New("AWS runtime credentials unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil {
		return errors.New("AWS runtime credentials unavailable")
	}
	c, err := parseAWSProcess(raw, time.Now(), 30*time.Second)
	if err != nil {
		return err
	}
	if c.Expiration == "" || c.SessionToken == "" {
		return errAWSLoginInvalid
	}
	return json.NewEncoder(os.Stdout).Encode(c)
}

// Renewal starts early and tolerates outages only while the last verified lease
// has a safe remaining lifetime. A changed identity never receives that grace.
func maintainAWSLogin(ctx context.Context, b awsLoginBinding, path string, c awsProcessCredentials, refresh func(context.Context, awsLoginBinding) (awsProcessCredentials, error)) error {
	for {
		delay := time.Minute
		var expiry time.Time
		if c.Expiration != "" {
			expiry, _ = time.Parse(time.RFC3339, c.Expiration)
			if remaining := time.Until(expiry.Add(-awsLoginReserve - 45*time.Second)); remaining < delay {
				delay = remaining
			}
		}
		if delay <= 0 {
			return errors.New("AWS login could not renew before the safety deadline; log in again on the coordinator")
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		next, err := refresh(ctx, b)
		if err == nil {
			if err = saveJSONAtomic(path, next); err != nil {
				return errors.New("could not rotate protected AWS credentials")
			}
			c = next
			continue
		}
		if errors.Is(err, errAWSLoginInvalid) {
			return err
		}
		// Retry without allowing a 45-second attempt to cross the safety deadline.
		for err != nil {
			if !expiry.IsZero() && time.Until(expiry) < awsLoginReserve+55*time.Second {
				return errors.New("AWS login renewal unavailable before expiry; log in again on the coordinator")
			}
			timer := time.NewTimer(10 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			next, err = refresh(ctx, b)
			if errors.Is(err, errAWSLoginInvalid) {
				return err
			}
		}
		if err = saveJSONAtomic(path, next); err != nil {
			return errors.New("could not rotate protected AWS credentials")
		}
		c = next
	}
}
