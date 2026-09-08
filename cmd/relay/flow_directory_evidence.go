package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// A bounded manifest binds names and bytes, including additions/removals.
// It is a local freshness check, not mathematical verification or erasure proof.
func flowTreeHash(root string) (string, error) {
	manifest := sha256.New()
	count := 0
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("public evidence tree contains a symlink")
		}
		if flowPrivateBasename(entry.Name()) {
			return errors.New("public evidence tree contains a private credential/key filename")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fmt.Fprintf(manifest, "%q\x00", filepath.ToSlash(rel))
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("public evidence tree contains a special file")
		}
		count++
		total += info.Size()
		if count > 10000 || total > 16<<30 {
			return errors.New("evidence tree exceeds local freshness-check limits; retain files and ask a maintainer to review")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		digest := sha256.New()
		written, copyErr := io.Copy(digest, io.LimitReader(file, info.Size()+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || written != info.Size() {
			return errors.New("evidence file changed or could not be read during snapshot")
		}
		fmt.Fprintf(manifest, "%d:%x\x00", written, digest.Sum(nil))
		return nil
	})
	return hex.EncodeToString(manifest.Sum(nil)), err
}

func (f *roleFlow) captureDirectories(task flowTask, command []string) (map[string]string, error) {
	result := map[string]string{}
	if f.state.Profile.Work == "" {
		return result, nil
	}
	for _, field := range append(append([]flowField{}, task.Fields...), task.ExtraFields...) {
		if !flowPublicDirectoryFlag(field.Flag) || flowOutputField(task, field) {
			continue
		}
		for n, arg := range command {
			if arg != "--"+field.Flag || n+1 >= len(command) {
				continue
			}
			value := command[n+1]
			if !strings.HasPrefix(value, "/work/") {
				return nil, errors.New("public evidence directories must be inside work")
			}
			local, err := f.publicHostPath(value)
			if err != nil {
				return nil, err
			}
			st, err := os.Lstat(local)
			if err != nil {
				return nil, err
			}
			if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
				return nil, errors.New("public evidence input must be a real directory")
			}
			digest, err := flowTreeHash(local)
			if err != nil {
				return nil, err
			}
			if strings.Contains(field.Flag, "transcript") {
				// Transcript growth is normal. Bind every retained file, allowing
				// new heads/beacons but never replacement or removal of old bytes.
				err = filepath.WalkDir(local, func(path string, e fs.DirEntry, err error) error {
					if err != nil || e.IsDir() {
						return err
					}
					rel, err := filepath.Rel(local, path)
					if err != nil {
						return err
					}
					digest, err := setupFileHash(path)
					if err != nil {
						return err
					}
					result["file:"+value+"/"+filepath.ToSlash(rel)] = digest
					return nil
				})
				if err != nil {
					return nil, err
				}
			} else {
				result[value] = digest
			}
		}
	}
	return result, nil
}

func (f *roleFlow) checkDirectoryBindings(bindings map[string]string) error {
	for value, digest := range bindings {
		local, err := f.publicHostPath(strings.TrimPrefix(value, "file:"))
		if err != nil {
			return err
		}
		var got string
		if strings.HasPrefix(value, "file:") {
			got, err = setupFileHash(local)
		} else {
			got, err = flowTreeHash(local)
		}
		if err != nil || got != digest {
			return fmt.Errorf("public evidence folder changed or is unavailable: %s; inspect and reverify", value)
		}
	}
	return nil
}
