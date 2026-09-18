package storagefirst

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/zksecurity/relay/internal/state"
)

// PublishLimits bounds concurrent artifact publication. InFlightBytes caps
// the combined size of the artifacts being staged and uploaded at once,
// because every in-flight artifact stages a full private copy on local disk;
// an artifact larger than the cap runs alone. Workers caps goroutines.
type PublishLimits struct {
	InFlightBytes int64
	Workers       int
}

// DefaultPublishLimits bounds staged bytes to 2 GiB across 8 workers, sized
// for production artifacts of up to 16 GiB each.
func DefaultPublishLimits() PublishLimits {
	return PublishLimits{InFlightBytes: 2 << 30, Workers: 8}
}

// PublishArtifacts publishes every referenced public artifact under root with
// bounded parallelism. Errors are deterministic: artifacts are processed in
// logical-name order and the first failure in that order is the one reported,
// regardless of which worker failed first. A failure stops artifacts that have
// not started, while running artifacts finish; because every key is
// content-addressed and created only if absent, retrying the whole batch is
// idempotent. The signed checkpoint, its signature, and the root pointer are
// published by the caller after this returns, so a partial batch never
// becomes discoverable.
func PublishArtifacts(objects ImmutableStore, refs []state.ContentRef, root, tempParent string, memo *VerifiedObjects, limits PublishLimits) error {
	if objects == nil {
		return errors.New("immutable object store is required")
	}
	if limits.InFlightBytes <= 0 || limits.Workers <= 0 {
		limits = DefaultPublishLimits()
	}
	// RequiredPublicArtifactsV4 already deduplicates by logical name; sorting
	// here makes both the processing order and the reported failure stable.
	ordered := append([]state.ContentRef(nil), refs...)
	slices.SortFunc(ordered, func(a, b state.ContentRef) int { return strings.Compare(a.Name, b.Name) })

	errs := make([]error, len(ordered))
	var failed atomic.Bool
	work := make(chan int)
	var group sync.WaitGroup
	bytes := newByteSemaphore(limits.InFlightBytes)
	workerCount := min(limits.Workers, len(ordered))
	for worker := 0; worker < workerCount; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range work {
				if failed.Load() {
					continue
				}
				ref := ordered[index]
				weight := max(min(ref.Size, limits.InFlightBytes), 0)
				bytes.acquire(weight)
				if failed.Load() {
					bytes.release(weight)
					continue
				}
				err := publishImmutableAt(objects, ref, root, tempParent, memo)
				bytes.release(weight)
				if err != nil {
					errs[index] = err
					failed.Store(true)
				}
			}
		}()
	}
	for index := range ordered {
		if failed.Load() {
			break
		}
		work <- index
	}
	close(work)
	group.Wait()

	for index, err := range errs {
		if err != nil {
			return fmt.Errorf("publish required public artifact %q: %w", ordered[index].Name, err)
		}
	}
	return nil
}

func publishImmutableAt(objects ImmutableStore, ref state.ContentRef, root, tempParent string, memo *VerifiedObjects) error {
	return PublishImmutable(objects, ref, filepath.Join(root, filepath.FromSlash(ref.Name)), tempParent, memo)
}

// byteSemaphore bounds a total quantity of in-flight work measured in bytes.
// Acquiring more than the capacity is allowed and blocks all other
// acquisitions, so a single oversized artifact runs alone instead of being
// rejected.
type byteSemaphore struct {
	mu   sync.Mutex
	cond *sync.Cond
	free int64
}

func newByteSemaphore(capacity int64) *byteSemaphore {
	s := &byteSemaphore{free: capacity}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *byteSemaphore) acquire(weight int64) {
	if weight <= 0 {
		return
	}
	s.mu.Lock()
	for s.free < weight {
		s.cond.Wait()
	}
	s.free -= weight
	s.mu.Unlock()
}

func (s *byteSemaphore) release(weight int64) {
	if weight <= 0 {
		return
	}
	s.mu.Lock()
	s.free += weight
	s.cond.Broadcast()
	s.mu.Unlock()
}
