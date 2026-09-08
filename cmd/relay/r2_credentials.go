package main

import (
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

// Credential contents never belong in Docker's configured environment or argv.
// Only the path of a narrowly mounted read-only file crosses that boundary.
// Consume either the legacy environment value or the file, never ambiguously both.
func consumeR2Credential(name string) (string, error) {
	value, file := os.Getenv(name), os.Getenv(name+"_FILE")
	if err := os.Unsetenv(name); err != nil {
		return "", errors.New("could not clear R2 credential environment")
	}
	if err := os.Unsetenv(name + "_FILE"); err != nil {
		return "", errors.New("could not clear R2 credential file environment")
	}
	if value != "" && file != "" {
		return "", errors.New("ambiguous R2 credential: supply a value or a protected file, not both")
	}
	if file == "" {
		return value, nil
	}
	return readProtectedCredential(file)
}

func readProtectedCredential(path string) (string, error) {
	raw, err := readProtectedCredentialBytes(path, 16384)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" || strings.ContainsAny(value, "\x00\r\n\t ") {
		return "", errors.New("credential file must contain one nonempty credential without whitespace")
	}
	return value, nil
}

func readProtectedCredentialBytes(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("cannot open protected credential file")
	}
	f := os.NewFile(uintptr(fd), "credential")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, errors.New("credential must be a private regular file within the size limit")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() || stat.Nlink != 1 {
		return nil, errors.New("credential file must belong to the current user and have no hard links")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("cannot read protected credential file")
	}
	return raw, nil
}
