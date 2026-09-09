package verification

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureManifest() (Manifest, map[string][]byte) {
	m := Manifest{Schema: Schema, CeremonyID: "sha256:" + strings.Repeat("a", 64), ReleaseKeyID: "release-key", Inputs: map[string]string{}}
	data := map[string][]byte{}
	for _, key := range RequiredInputs {
		p := "data/" + key
		if key == "transcript-root" || key == "keys-dir" {
			m.Inputs[key] = p
			p += "/file"
		} else {
			m.Inputs[key] = p
		}
		data[p] = []byte(key)
	}
	for p, b := range data {
		h := sha256.Sum256(b)
		f := File{Path: p, Size: int64(len(b)), SHA256: hex.EncodeToString(h[:])}
		m.Files = append(m.Files, f)
		if p == m.Inputs["ceremony"] {
			m.DefinitionSHA256 = f.SHA256
		}
	}
	return m, data
}
func archiveFixture(t *testing.T, m Manifest, data map[string][]byte, extra string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ceremony.zip")
	out, e := os.Create(p)
	if e != nil {
		t.Fatal(e)
	}
	z := zip.NewWriter(out)
	raw, _ := json.Marshal(m)
	w, _ := z.Create("verification.json")
	w.Write(raw)
	for name, b := range data {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		w.Write(b)
	}
	if extra != "" {
		w, _ := z.Create(extra)
		w.Write([]byte("extra"))
	}
	if e := z.Close(); e != nil {
		t.Fatal(e)
	}
	out.Close()
	return p
}
func TestArchiveIntegrityAndBoundaries(t *testing.T) {
	m, data := fixtureManifest()
	p := archiveFixture(t, m, data, "")
	root, got, e := Extract(p, 1<<20)
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(root)
	if got.CeremonyID != m.CeremonyID {
		t.Fatal("identity changed")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Manifest, map[string][]byte)
		extra  string
		limit  int64
	}{
		{"tamper", func(_ *Manifest, d map[string][]byte) { d["data/ceremony"] = []byte("modified") }, "", 1 << 20},
		{"missing", func(_ *Manifest, d map[string][]byte) { delete(d, "data/ceremony") }, "", 1 << 20},
		{"unlisted", func(_ *Manifest, _ map[string][]byte) {}, "unexpected", 1 << 20},
		{"escape", func(_ *Manifest, _ map[string][]byte) {}, "../outside", 1 << 20},
		{"duplicate", func(_ *Manifest, _ map[string][]byte) {}, "data/ceremony", 1 << 20},
		{"byte-limit", func(_ *Manifest, _ map[string][]byte) {}, "", 10},
		{"case-collision", func(m *Manifest, d map[string][]byte) {
			m.Files = append(m.Files, File{Path: "DATA/ceremony", Size: 0, SHA256: strings.Repeat("b", 64)})
			d["DATA/ceremony"] = nil
		}, "", 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, d := fixtureManifest()
			tc.mutate(&m, d)
			root, _, e := Extract(archiveFixture(t, m, d, tc.extra), tc.limit)
			if e == nil {
				os.RemoveAll(root)
				t.Fatal("accepted invalid archive")
			}
		})
	}
}
func TestManifestRejectsAmbiguousAndExecutableInputs(t *testing.T) {
	m, _ := fixtureManifest()
	raw, _ := json.Marshal(m)
	for _, bad := range [][]byte{[]byte(strings.Replace(string(raw), `"schema":`, `"schema":"duplicate","schema":`, 1)), append(raw, []byte(` {}`)...)} {
		if _, e := Parse(bad); e == nil {
			t.Fatal("accepted ambiguous manifest")
		}
	}
	m.Inputs["command"] = "run.sh"
	if e := m.Validate(); e == nil {
		t.Fatal("accepted executable selector")
	}
	for _, p := range []string{"/etc/file", "../file", "a/../file", `a\b`, "a//b", "a/./b", "a:b", "file."} {
		if SafePath(p) {
			t.Fatalf("accepted %q", p)
		}
	}
}

func TestArchiveRejectsLinksAndDeepManifest(t *testing.T) {
	m, data := fixtureManifest()
	raw, _ := json.Marshal(m)
	deep := []byte(strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17))
	if _, err := Parse(deep); err == nil {
		t.Fatal("deep manifest accepted")
	}
	p := filepath.Join(t.TempDir(), "link.zip")
	file, _ := os.Create(p)
	z := zip.NewWriter(file)
	w, _ := z.Create("verification.json")
	w.Write(raw)
	for name, b := range data {
		header := &zip.FileHeader{Name: name}
		if name == "data/ceremony" {
			header.SetMode(os.ModeSymlink | 0600)
		} else {
			header.SetMode(0600)
		}
		w, _ := z.CreateHeader(header)
		w.Write(b)
	}
	z.Close()
	file.Close()
	if root, _, err := Extract(p, 1<<20); err == nil {
		os.RemoveAll(root)
		t.Fatal("symlink accepted")
	}
}
