package main

import (
	"errors"
	"github.com/zksecurity/relay/internal/upgrade"
	"strings"
)

// Only a verified local selection relaxes an entry point's exact app-release
// check. The original release check remains unchanged everywhere else.
func checkPreparationRelease(name, role, tag, work, trust, keys string) error {
	history, _, err := upgradeV2ReadHistory(work)
	if err != nil {
		return err
	}
	if len(history) == 0 {
		return checkLauncherRelease(strings.TrimPrefix(tag, "role-images-"))
	}
	s := history[0]
	if s.Profile.Name != name || s.Profile.Role != role || s.Profile.Work != work || s.Profile.Trust != trust || s.Profile.Keys != keys || s.Profile.ReleaseCommit != strings.TrimPrefix(tag, "role-images-") {
		return errors.New("preparation does not match the selected ceremony application")
	}
	_, _, _, err = upgradeV2Selected(s.Profile, s.SettingsRoot, true)
	return err
}

func upgradeV2NewActionImage(p guidedProfile, command []string) string {
	if p.UpgradeOnlineImage != "" && len(command) > 0 && command[0] == "relay" {
		switch p.Role {
		case "coordinator", "auditor", "witness", "mirror", "upload-station":
			return p.UpgradeOnlineImage
		}
	}
	return p.Image
}

func upgradeV2SavedActionImage(p guidedProfile, path, action string) (string, error) {
	saved, err := readGuidedProfile(path, action, "action")
	if err != nil {
		return "", err
	}
	if saved.Image == "" {
		return p.Image, nil
	} // pre-update actions retain original runtime
	if saved.Platform != p.Platform {
		return "", errors.New("saved action changed platform")
	}
	if saved.Image == p.Image {
		return p.Image, nil
	}
	if len(saved.Command) == 0 || saved.Command[0] != "relay" || p.Role == "participant" || p.Role == "release-signer" || p.Role == "decision-signer" || p.Role == "keygen" {
		return "", errors.New("saved cryptographic action changed runtime")
	}
	history, _, err := upgradeV2ReadHistory(p.Work)
	if err != nil {
		return "", err
	}
	for _, s := range history {
		d, err := upgrade.DecodeV2(s.Declaration)
		if err != nil {
			return "", err
		}
		if d.Role == p.Role && d.Platform == p.Platform && d.OnlineImage == saved.Image {
			return saved.Image, nil
		}
	}
	return "", errors.New("saved action runtime has no retained compatibility authorization")
}

func verifiedWorkspaceReleaseImage(tag, role, platform, work, trust, keys string) (string, string, error) {
	selectionWork, err := upgradeV2SelectionWork(guidedProfile{Role: role, Work: work, ReleaseCommit: strings.TrimPrefix(tag, "role-images-")})
	if err != nil {
		return "", "", err
	}
	history, _, err := upgradeV2ReadHistory(selectionWork)
	if err != nil {
		return "", "", err
	}
	if len(history) == 0 {
		return verifiedReleaseImage(tag, role, platform)
	}
	s := history[0]
	keygen := role == "keygen" && s.Profile.Keys == work && keys == "" && trust == ""
	if s.Profile.ReleaseCommit != strings.TrimPrefix(tag, "role-images-") || (!keygen && (s.Profile.Work != work || s.Profile.Trust != trust || s.Profile.Keys != keys)) || s.Profile.Platform != platform {
		return "", "", errors.New("setup folders or release differ from the selected workspace")
	}
	_, d, _, err := upgradeV2Selected(s.Profile, s.SettingsRoot, true)
	if err != nil {
		return "", "", err
	}
	if role != d.Role && role != "decision-signer" && role != "keygen" {
		return "", "", errors.New("application selection does not authorize another role")
	}
	// Setup always saves the original runtime. Online Relay dispatch is resolved
	// separately at execution; it never rewrites the cryptographic profile.
	image, err := selectReleaseImage(s.OriginalMap, d.OriginalRelease, role, platform)
	return image, d.OriginalRelease, err
}
