package storagefirst

import (
	"context"
	"io"
)

// Check between bounded copy/hash reads; regular-file reads themselves are
// synchronous and cannot be interrupted while the kernel is serving a read.
type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
