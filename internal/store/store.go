// Package store wraps the S3-compatible object operations this tool needs.
//
// It shells out to the AWS CLI rather than linking an SDK. That keeps the
// dependency surface at zero, which matters for a tool whose whole claim is
// that it cannot influence the ceremony: there is nothing here to audit beyond
// the process invocations, and credentials stay in the CLI's own profile store
// rather than passing through this program.
//
// Every object is addressed by content: blob/sha256/<hex>. A location is
// therefore derivable from the signed chain rather than trusted, and two
// uploads of the same bytes collide on the same key instead of racing.
package store

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

type Client struct {
	Profile  string
	Endpoint string
	Bucket   string
}

// Key returns the content-addressed object key for a tagged sha256 digest.
func Key(taggedSHA256 string) string {
	return "blob/sha256/" + strings.TrimPrefix(taggedSHA256, "sha256:")
}

func (c Client) args(rest ...string) []string {
	base := []string{"--profile", c.Profile, "--endpoint-url", c.Endpoint, "s3api"}
	return append(base, rest...)
}

func (c Client) run(args ...string) ([]byte, error) {
	cmd := exec.Command("aws", c.args(args...)...)
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
// silently replacing published bytes. Because keys are content-addressed, an
// existing key means identical content, so ErrExists is a success for the
// caller's purposes but is reported rather than hidden.
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
	_, err := c.run("get-object", "--bucket", c.Bucket, "--key", key, localPath)
	return err
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
