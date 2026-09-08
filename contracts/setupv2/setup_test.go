package setupv2

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSharedFixtures(t *testing.T) {
	raw, err := os.ReadFile("fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name   string
		JSON   string
		Valid  bool
		Input  string `json:"input_sha256"`
		SHA    string `json:"sha256"`
		Result string `json:"result_sha256"`
	}
	if err = json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			s, err := Parse([]byte(f.JSON))
			if !f.Valid {
				if err == nil {
					t.Fatal("invalid setup accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			input, err := s.InputDigest()
			if err != nil || input != f.Input {
				t.Fatalf("input digest %s: %v", input, err)
			}
			sha, err := s.Digest()
			if err != nil || sha != f.SHA {
				t.Fatalf("setup digest %s: %v", sha, err)
			}
			if s.Result != nil {
				result, err := s.Result.Digest()
				if err != nil || result != f.Result {
					t.Fatalf("result digest %s: %v", result, err)
				}
			}
		})
	}
}
func TestBoundsAndUTF8(t *testing.T) {
	for _, b := range [][]byte{[]byte(strings.Repeat(" ", MaxBytes+1)), {'"', 0xff, '"'}} {
		if _, err := Parse(b); err == nil {
			t.Fatal("invalid bytes accepted")
		}
	}
}
