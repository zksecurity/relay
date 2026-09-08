package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// GetSized constrains an inbox evidence download to its declared size. The
// caller still checks the cryptographic digest; provider metadata isn't proof.
func (c Client) GetSized(key, local string, size int64) error {
	if size < 0 || size > 16<<30 || c.PublicBaseURL != "" {
		return errors.New("invalid bounded inbox download")
	}
	if _, err := os.Lstat(local); !os.IsNotExist(err) {
		return errors.New("download destination must be fresh")
	}
	raw, err := c.run("head-object", "--bucket", c.Bucket, "--key", key, "--query", "ContentLength", "--output", "json")
	if err != nil {
		return err
	}
	var length *int64
	if json.Unmarshal(raw, &length) != nil || length == nil || *length != size {
		return errors.New("inbox object size differs from manifest")
	}
	if size == 0 {
		file, err := os.OpenFile(local, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		return file.Close()
	}
	// One extra byte detects growth between HEAD and GET without downloading
	// an unbounded replacement object. The S3/R2 endpoint must honor Range.
	_, err = c.run("get-object", "--bucket", c.Bucket, "--key", key, "--range", fmt.Sprintf("bytes=0-%d", size), local)
	return err
}
