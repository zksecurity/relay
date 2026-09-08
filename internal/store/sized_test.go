package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSizedDownloadChecksMetadataAndBoundsRange(t *testing.T) {
	for _, metadata := range []string{"3", "4", "null"} {
		t.Run(metadata, func(t *testing.T) {
			dir := t.TempDir()
			log := filepath.Join(dir, "calls")
			script := `#!/bin/sh
printf '%s\n' "$*" >> "$RELAY_TEST_CALLS"
case " $* " in
 *" head-object "*) printf '%s\n' "$RELAY_TEST_SIZE" ;;
 *) for arg do destination=$arg; done; printf abc > "$destination" ;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "aws"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("RELAY_TEST_SIZE", metadata)
			t.Setenv("RELAY_TEST_CALLS", log)
			err := (Client{Bucket: "test"}).GetSized("files/probe", filepath.Join(dir, "out"), 3)
			if (err == nil) != (metadata == "3") {
				t.Fatal(metadata, err)
			}
			raw, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			if metadata == "3" && !strings.Contains(string(raw), "--range bytes=0-3") {
				t.Fatal("unbounded download")
			}
			if metadata != "3" && strings.Contains(string(raw), "get-object") {
				t.Fatal("download proceeded despite invalid size")
			}
		})
	}
}
