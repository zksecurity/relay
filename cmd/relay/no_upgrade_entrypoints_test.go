package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestNeverUpgradedEntryPointsAndSavedImages(t *testing.T) {
	for _, role := range []string{"coordinator", "participant", "witness", "mirror", "auditor", "release-signer", "upload-station", "decision-signer", "keygen"} {
		t.Run(role, func(t *testing.T) {
			root := privateRoleTestDir(t)
			work := filepath.Join(root, "work")
			if err := os.Mkdir(work, 0700); err != nil {
				t.Fatal(err)
			}
			p := guidedProfile{Schema: guidedSchema, Name: "ordinary", Role: role, Work: work, Image: "sha256:" + strings.Repeat("b", 64), Platform: "linux/arm64", ReleaseCommit: launcherCommit()}
			got, err := applyCeremonyUpgrade(p, root)
			if err != nil || !reflect.DeepEqual(got, p) {
				t.Fatalf("ordinary profile changed: %+v %v", got, err)
			}
			if err := checkPreparationRelease(p.Name, p.Role, "role-images-"+p.ReleaseCommit, p.Work, p.Trust, p.Keys); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"identity", "definition", "storage", "initialization"} {
				files, err := upgradeV2CaptureSetup(work, kind)
				if err != nil || files != nil {
					t.Fatalf("ordinary setup captured extra state: %v %v", files, err)
				}
			}
			files, err := os.ReadDir(work)
			if err != nil || len(files) != 0 {
				t.Fatalf("startup wrote files: %v %v", files, err)
			}
			command := []string{"mpc-ceremony", "inspect", "definition"}
			// A pre-update action has no saved image. It must keep the profile image.
			if _, _, err := prepareGuidedAction(root, "old", command); err != nil {
				t.Fatal(err)
			}
			oldPath := filepath.Join(root, "actions", "old", "profile.json")
			before, err := os.ReadFile(oldPath)
			if err != nil {
				t.Fatal(err)
			}
			image, err := upgradeV2SavedActionImage(p, oldPath, "old")
			if err != nil || image != p.Image {
				t.Fatalf("old runtime changed: %s %v", image, err)
			}
			after, _ := os.ReadFile(oldPath)
			if string(before) != string(after) {
				t.Fatal("old action rewritten")
			}
			// New actions pin the same image and remain readable by the original schema.
			if _, _, err := prepareGuidedAction(root, "new", command, p); err != nil {
				t.Fatal(err)
			}
			newPath := filepath.Join(root, "actions", "new", "profile.json")
			saved, err := readGuidedProfile(newPath, "new", "action")
			if err != nil || saved.Image != p.Image || saved.Platform != p.Platform {
				t.Fatalf("new action: %+v %v", saved, err)
			}
			image, err = upgradeV2SavedActionImage(p, newPath, "new")
			if err != nil || image != p.Image {
				t.Fatalf("new runtime changed: %s %v", image, err)
			}
		})
	}
}
