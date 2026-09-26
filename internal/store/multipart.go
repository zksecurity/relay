package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const publicationPartSize = int64(128 << 20)

// PutLargeNoReplace uses a conditional CompleteMultipartUpload. A HEAD check
// followed by `aws s3 cp` is unsafe here: another writer can win between them.
// Callers must reread and compare the complete public object after every result,
// including an uncertain completion or an existing key.
func (c Client) PutLargeNoReplace(key, localPath, work string) error {
	file, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("publication source must be a regular file")
	}
	if info.Size() <= 4<<30 {
		return c.PutNoReplace(key, localPath)
	}
	return c.putMultipartNoReplace(file, info.Size(), key, work, publicationPartSize)
}

func (c Client) putMultipartNoReplace(file *os.File, size int64, key, work string, partSize int64) error {
	if partSize < 5<<20 || partSize > 5<<30 || size <= 0 || (size+partSize-1)/partSize > 10000 {
		return errors.New("publication archive exceeds the supported multipart limit")
	}
	raw, err := c.run("create-multipart-upload", "--bucket", c.Bucket, "--key", key, "--output", "json")
	if err != nil {
		return err
	}
	var created struct {
		UploadID string `json:"UploadId"`
	}
	if json.Unmarshal(raw, &created) != nil || created.UploadID == "" {
		return errors.New("storage did not return a multipart upload ID")
	}
	completed := false
	defer func() {
		if !completed {
			_, _ = c.run("abort-multipart-upload", "--bucket", c.Bucket, "--key", key, "--upload-id", created.UploadID)
		}
	}()
	type part struct {
		ETag       string `json:"ETag"`
		PartNumber int    `json:"PartNumber"`
	}
	parts := []part{}
	for offset, number := int64(0), 1; offset < size; offset, number = offset+partSize, number+1 {
		partFile, err := os.CreateTemp(work, ".go-publication-part-*")
		if err != nil {
			return err
		}
		partName := partFile.Name()
		count := min(partSize, size-offset)
		_, copyErr := io.CopyN(partFile, io.NewSectionReader(file, offset, count), count)
		closeErr := partFile.Close()
		if copyErr != nil || closeErr != nil {
			_ = os.Remove(partName)
			return errors.New("failed to stage multipart publication bytes")
		}
		response, uploadErr := c.run("upload-part", "--bucket", c.Bucket, "--key", key, "--upload-id", created.UploadID, "--part-number", fmt.Sprint(number), "--body", partName, "--output", "json")
		_ = os.Remove(partName)
		if uploadErr != nil {
			return uploadErr
		}
		var uploaded struct {
			ETag string `json:"ETag"`
		}
		if json.Unmarshal(response, &uploaded) != nil || uploaded.ETag == "" {
			return errors.New("storage did not return a multipart part ETag")
		}
		parts = append(parts, part{ETag: uploaded.ETag, PartNumber: number})
	}
	manifest, err := os.CreateTemp(work, ".go-publication-parts-*")
	if err != nil {
		return err
	}
	defer os.Remove(manifest.Name())
	if err := json.NewEncoder(manifest).Encode(map[string]any{"Parts": parts}); err != nil {
		manifest.Close()
		return err
	}
	if err := manifest.Close(); err != nil {
		return err
	}
	_, err = c.run("complete-multipart-upload", "--bucket", c.Bucket, "--key", key, "--upload-id", created.UploadID, "--multipart-upload", "file://"+filepath.Clean(manifest.Name()), "--if-none-match", "*")
	if err != nil {
		return fmt.Errorf("conditional multipart completion uncertain or rejected: %w", err)
	}
	completed = true
	return nil
}

// ProbeMultipartWrite checks that the chosen credential can start and abort a
// multipart upload at this exact key. It creates no public object and must
// finish before the human publication confirmation is requested.
func (c Client) ProbeMultipartWrite(key string) error {
	raw, err := c.run("create-multipart-upload", "--bucket", c.Bucket, "--key", key, "--output", "json")
	if err != nil {
		return fmt.Errorf("probe publication upload access: %w", err)
	}
	var created struct {
		UploadID string `json:"UploadId"`
	}
	if json.Unmarshal(raw, &created) != nil || created.UploadID == "" {
		return errors.New("publication access probe did not return an upload ID")
	}
	if _, err := c.run("abort-multipart-upload", "--bucket", c.Bucket, "--key", key, "--upload-id", created.UploadID); err != nil {
		return fmt.Errorf("could not abort publication access probe: %w", err)
	}
	return nil
}
