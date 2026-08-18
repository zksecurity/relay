// Package store wraps the S3-compatible object operations this tool needs.
//
// It shells out to the AWS CLI rather than linking an SDK. That keeps the
// dependency surface at zero, which matters for a tool whose whole claim is
// that it cannot influence the ceremony. Coordinator credentials remain in an
// AWS CLI profile. Short-lived role credentials are held in a mode-0600 grant
// and exposed only in the child AWS CLI process environment, never in argv.
//
// Every object is addressed by content: blob/sha256/<hex>. A location is
// therefore derivable from the signed chain rather than trusted, and two
// uploads of the same bytes collide on the same key instead of racing.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

type Client struct {
	Profile       string
	Endpoint      string
	Region        string
	Bucket        string
	PublicBaseURL string
	Credentials   *Credentials
	NoSign        bool
}

// Key returns the content-addressed object key for a tagged sha256 digest.
func Key(taggedSHA256 string) string {
	return "blob/sha256/" + strings.TrimPrefix(taggedSHA256, "sha256:")
}

func (c Client) args(rest ...string) []string {
	var base []string
	if c.Profile != "" {
		base = append(base, "--profile", c.Profile)
	}
	if c.Endpoint != "" {
		base = append(base, "--endpoint-url", c.Endpoint)
	}
	if c.Region != "" {
		base = append(base, "--region", c.Region)
	}
	if c.NoSign {
		base = append(base, "--no-sign-request")
	}
	base = append(base, "s3api")
	return append(base, rest...)
}

func (c Client) run(args ...string) ([]byte, error) {
	cmd := exec.Command("aws", c.args(args...)...)
	if c.Credentials != nil {
		cmd.Env = append(os.Environ(),
			"AWS_ACCESS_KEY_ID="+c.Credentials.AccessKeyID,
			"AWS_SECRET_ACCESS_KEY="+c.Credentials.SecretAccessKey,
			"AWS_SESSION_TOKEN="+c.Credentials.SessionToken,
		)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("aws %s: %w: %s",
			strings.Join(args[:1], " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// ErrExists reports that the key was already present and was left untouched.
var ErrExists = errors.New("object already exists")

// PutNoReplace uploads a file only if the key does not already exist.
//
// If-None-Match is the object-storage equivalent of the ceremony's
// RENAME_NOREPLACE: a retry that would overwrite fails loudly instead of
// silently replacing bytes. Content-addressed callers can treat ErrExists as
// an honest retry; identity-scoped submission callers reject it as a collision.
func (c Client) PutNoReplace(key, localPath string) error {
	_, err := c.run("put-object",
		"--bucket", c.Bucket,
		"--key", key,
		"--body", localPath,
		"--if-none-match", "*")
	if err == nil {
		return nil
	}
	// Providers refuse a create-only write to an existing key in more than one
	// way. S3 and R2 return PreconditionFailed for the conditional header, but
	// R2 with bucket locks configured rejects the overwrite before evaluating
	// the condition and returns ObjectLockedByBucketPolicy instead. Rather than
	// enumerate error strings, ask whether the key is present: because keys are
	// content-addressed, an existing key holds identical bytes, so a refused
	// write is a no-op rather than a failure.
	present, headErr := c.Head(key)
	if headErr == nil && present {
		return ErrExists
	}
	return err
}

// Get downloads an object to a local path.
func (c Client) Get(key, localPath string) error {
	if c.PublicBaseURL != "" {
		return c.getPublic(key, localPath)
	}
	_, err := c.run("get-object", "--bucket", c.Bucket, "--key", key, localPath)
	return err
}

func (c Client) getPublic(key, localPath string) error {
	if key == "" || path.Clean(key) != key || strings.HasPrefix(key, "../") || strings.Contains(key, `\`) {
		return fmt.Errorf("unsafe public object key %q", key)
	}
	base, err := url.Parse(c.PublicBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" {
		return errors.New("invalid public base URL")
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/" + key
	response, err := http.Get(base.String()) // #nosec G107 -- base is operator configuration validated as HTTPS.
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("GET %s: HTTP %s", key, response.Status)
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, response.Body)
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(localPath)
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	return nil
}

// Head reports whether a key exists.
func (c Client) Head(key string) (bool, error) {
	_, err := c.run("head-object", "--bucket", c.Bucket, "--key", key)
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "Not Found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// Put writes an object, replacing any existing one.
//
// This is used only for the mutable state pointer, which must be overwritable
// because it is how the ceremony advances. Every content-addressed blob goes
// through PutNoReplace instead, so published bytes are never replaced.
func (c Client) Put(key, localPath string) error {
	_, err := c.run("put-object", "--bucket", c.Bucket, "--key", key, "--body", localPath)
	return err
}

// Delete removes one explicitly named object. It is used only for disposable
// storage preflight probes, never for transcript or role-submitted evidence.
func (c Client) Delete(key string) error {
	_, err := c.run("delete-object", "--bucket", c.Bucket, "--key", key)
	return err
}

type Object struct {
	Key  string
	Size int64
}

// List returns objects under an exact prefix. Callers still validate every
// returned key before treating it as a candidate or evidence submission.
func (c Client) List(prefix string) ([]Object, error) {
	var objects []Object
	var continuation string
	for {
		args := []string{"list-objects-v2", "--bucket", c.Bucket, "--prefix", prefix, "--output", "json"}
		if continuation != "" {
			args = append(args, "--continuation-token", continuation)
		}
		raw, err := c.run(args...)
		if err != nil {
			return nil, err
		}
		var result struct {
			Contents []struct {
				Key  string `json:"Key"`
				Size int64  `json:"Size"`
			} `json:"Contents"`
			IsTruncated           bool   `json:"IsTruncated"`
			NextContinuationToken string `json:"NextContinuationToken"`
		}
		if err := json.Unmarshal(raw, &result); err != nil {
			return nil, fmt.Errorf("decode object listing: %w", err)
		}
		for _, object := range result.Contents {
			objects = append(objects, Object{Key: object.Key, Size: object.Size})
		}
		if !result.IsTruncated {
			return objects, nil
		}
		if result.NextContinuationToken == "" || result.NextContinuationToken == continuation {
			return nil, errors.New("object listing was truncated without a fresh continuation token")
		}
		continuation = result.NextContinuationToken
	}
}
