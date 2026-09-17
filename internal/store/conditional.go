package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// ErrVersionConflict reports that a conditional replacement did not match the
// exact object version previously read. Callers must resynchronize; retrying
// with a different version would be a different state transition.
var ErrVersionConflict = errors.New("object version conflict")

// publicReadTimeout bounds a single read from the unauthenticated public
// distribution endpoint. The synchronizer can safely retry a failed read, but
// must never let one stalled CDN connection hold a role workflow forever.
var publicReadTimeout = 30 * time.Second

// ObjectVersion is the storage-provider version returned with an object read
// or write. ETag is the conditional-write token used by S3 and R2. VersionID is
// retained when the provider supplies one so recovery records can identify the
// exact read more precisely.
type ObjectVersion struct {
	ETag      string `json:"etag"`
	VersionID string `json:"version_id,omitempty"`
	Size      int64  `json:"size"`
}

func validateVersion(version ObjectVersion) error {
	if version.ETag == "" || len(version.ETag) > 1024 || strings.ContainsAny(version.ETag, "\x00\r\n") {
		return errors.New("object version has an invalid ETag")
	}
	if len(version.VersionID) > 1024 || strings.ContainsAny(version.VersionID, "\x00\r\n") {
		return errors.New("object version has an invalid version ID")
	}
	if version.Size < 0 {
		return errors.New("object version has a negative size")
	}
	return nil
}

func validateKey(key string) error {
	if key == "" || len(key) > 1024 || path.Clean(key) != key || strings.HasPrefix(key, "/") ||
		key == ".." || strings.HasPrefix(key, "../") || strings.ContainsAny(key, "\\\x00\r\n") {
		return fmt.Errorf("unsafe object key %q", key)
	}
	return nil
}

// HeadVersion returns the current authenticated provider metadata. It is not a
// substitute for downloading and verifying the object bytes.
func (c Client) HeadVersion(key string) (ObjectVersion, error) {
	if c.PublicBaseURL != "" {
		return ObjectVersion{}, errors.New("versioned provider metadata requires authenticated object storage")
	}
	if err := validateKey(key); err != nil {
		return ObjectVersion{}, err
	}
	raw, err := c.run("head-object", "--bucket", c.Bucket, "--key", key, "--output", "json")
	if err != nil {
		return ObjectVersion{}, err
	}
	var response struct {
		ETag          string `json:"ETag"`
		VersionID     string `json:"VersionId"`
		ContentLength *int64 `json:"ContentLength"`
	}
	if err := json.Unmarshal(raw, &response); err != nil || response.ContentLength == nil {
		return ObjectVersion{}, errors.New("object storage returned invalid version metadata")
	}
	version := ObjectVersion{ETag: response.ETag, VersionID: response.VersionID, Size: *response.ContentLength}
	if err := validateVersion(version); err != nil {
		return ObjectVersion{}, err
	}
	return version, nil
}

// GetVersionedAtMost downloads a small object without allowing it to grow past
// maximum. Authenticated reads pin the HEAD result with If-Match (and the
// provider version ID when present), so a replacement between HEAD and GET is
// rejected rather than mixed into the caller's state transition. Public reads
// are bounded in the HTTP stream and return any ETag supplied by the origin.
func (c Client) GetVersionedAtMost(key, local string, maximum int64) (ObjectVersion, error) {
	if maximum < 0 || maximum > 16<<30 {
		return ObjectVersion{}, errors.New("invalid bounded download limit")
	}
	if c.PublicBaseURL != "" {
		return c.getPublicVersionedAtMost(key, local, maximum)
	}
	if _, err := os.Lstat(local); !errors.Is(err, os.ErrNotExist) {
		return ObjectVersion{}, errors.New("download destination must be fresh")
	}
	version, err := c.HeadVersion(key)
	if err != nil {
		return ObjectVersion{}, err
	}
	if version.Size > maximum {
		return ObjectVersion{}, errors.New("object exceeds download limit")
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
		return ObjectVersion{}, err
	}
	args := []string{"get-object", "--bucket", c.Bucket, "--key", key, "--if-match", version.ETag}
	if version.VersionID != "" && version.VersionID != "null" {
		args = append(args, "--version-id", version.VersionID)
	}
	args = append(args, "--output", "json", local)
	raw, err := c.run(args...)
	if err != nil {
		_ = os.Remove(local)
		if conditionalFailure(err) {
			return ObjectVersion{}, fmt.Errorf("%w: object changed during bounded read", ErrVersionConflict)
		}
		return ObjectVersion{}, err
	}
	var downloaded struct {
		ETag      string `json:"ETag"`
		VersionID string `json:"VersionId"`
	}
	if len(bytes.TrimSpace(raw)) != 0 {
		if err := json.Unmarshal(raw, &downloaded); err != nil {
			_ = os.Remove(local)
			return ObjectVersion{}, errors.New("object storage returned invalid download metadata")
		}
		if downloaded.ETag != "" && downloaded.ETag != version.ETag {
			_ = os.Remove(local)
			return ObjectVersion{}, fmt.Errorf("%w: downloaded ETag differs from the pinned read", ErrVersionConflict)
		}
		if version.VersionID != "" && version.VersionID != "null" && downloaded.VersionID != "" && downloaded.VersionID != version.VersionID {
			_ = os.Remove(local)
			return ObjectVersion{}, fmt.Errorf("%w: downloaded version differs from the pinned read", ErrVersionConflict)
		}
	}
	info, err := os.Lstat(local)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != version.Size {
		_ = os.Remove(local)
		return ObjectVersion{}, errors.New("downloaded object size or file type differs from version metadata")
	}
	return version, nil
}

func (c Client) getPublicVersionedAtMost(key, local string, maximum int64) (ObjectVersion, error) {
	if err := validateKey(key); err != nil {
		return ObjectVersion{}, err
	}
	if _, err := os.Lstat(local); !errors.Is(err, os.ErrNotExist) {
		return ObjectVersion{}, errors.New("download destination must be fresh")
	}
	base, err := url.Parse(c.PublicBaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return ObjectVersion{}, errors.New("invalid public base URL")
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + "/" + key
	origin := base.Scheme + "://" + base.Host
	client := http.DefaultClient
	if c.httpClient != nil {
		client = c.httpClient
	}
	boundedClient := *client
	boundedClient.Timeout = publicReadTimeout
	boundedClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme+"://"+req.URL.Host != origin {
			return errors.New("public object redirect left the configured origin")
		}
		return nil
	}
	// Client.Timeout is a useful backstop, but make the deadline explicit on
	// the request as well. That ensures custom transports and blocked response
	// bodies receive cancellation rather than leaving a synchronizer stranded.
	ctx, cancel := context.WithTimeout(context.Background(), publicReadTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil) // #nosec G107 -- validated operator-configured HTTPS origin.
	if err != nil {
		return ObjectVersion{}, err
	}
	response, err := boundedClient.Do(request)
	if err != nil {
		return ObjectVersion{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return ObjectVersion{}, fmt.Errorf("GET %s: HTTP %s", key, response.Status)
	}
	if response.ContentLength > maximum {
		return ObjectVersion{}, errors.New("object exceeds download limit")
	}
	if err := os.MkdirAll(filepath.Dir(local), 0o700); err != nil {
		return ObjectVersion{}, err
	}
	file, err := os.OpenFile(local, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ObjectVersion{}, err
	}
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, maximum+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > maximum || (response.ContentLength >= 0 && written != response.ContentLength) {
		_ = os.Remove(local)
		switch {
		case copyErr != nil:
			return ObjectVersion{}, copyErr
		case closeErr != nil:
			return ObjectVersion{}, closeErr
		default:
			return ObjectVersion{}, errors.New("public object exceeded its limit or changed length during download")
		}
	}
	return ObjectVersion{ETag: response.Header.Get("ETag"), Size: written}, nil
}

// PutIfAbsent creates an object only when no object already exists at key.
// Unlike PutNoReplace, it never turns an unrelated provider failure into an
// existence result by performing a later HEAD request.
func (c Client) PutIfAbsent(key, local string) (ObjectVersion, error) {
	return c.putConditional(key, local, "", ErrExists)
}

// PutIfMatch replaces an object only when its current ETag is the exact token
// obtained by the caller's earlier versioned read.
func (c Client) PutIfMatch(key, local string, expected ObjectVersion) (ObjectVersion, error) {
	if err := validateVersion(expected); err != nil {
		return ObjectVersion{}, err
	}
	return c.putConditional(key, local, expected.ETag, ErrVersionConflict)
}

func (c Client) putConditional(key, local, match string, conflict error) (ObjectVersion, error) {
	if c.PublicBaseURL != "" {
		return ObjectVersion{}, errors.New("conditional writes require authenticated object storage")
	}
	if err := validateKey(key); err != nil {
		return ObjectVersion{}, err
	}
	info, err := os.Lstat(local)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ObjectVersion{}, errors.New("conditional upload source must be a regular non-symlink file")
	}
	args := []string{"put-object", "--bucket", c.Bucket, "--key", key, "--body", local}
	if match == "" {
		args = append(args, "--if-none-match", "*")
	} else {
		args = append(args, "--if-match", match)
	}
	args = append(args, "--output", "json")
	raw, err := c.run(args...)
	if err != nil {
		if conditionalFailure(err) {
			return ObjectVersion{}, fmt.Errorf("%w: conditional object write was refused", conflict)
		}
		return ObjectVersion{}, err
	}
	var response struct {
		ETag      string `json:"ETag"`
		VersionID string `json:"VersionId"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return ObjectVersion{}, errors.New("object storage returned invalid write metadata")
	}
	version := ObjectVersion{ETag: response.ETag, VersionID: response.VersionID, Size: info.Size()}
	if err := validateVersion(version); err != nil {
		return ObjectVersion{}, err
	}
	return version, nil
}

func conditionalFailure(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "preconditionfailed") ||
		strings.Contains(message, "conditionalrequestconflict") ||
		strings.Contains(message, "precondition failed") ||
		strings.Contains(message, "http 409") || strings.Contains(message, "http 412") ||
		strings.Contains(message, "status code: 409") || strings.Contains(message, "status code: 412")
}
