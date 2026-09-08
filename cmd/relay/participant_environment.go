package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// The environment is an unsigned plan until proof-tool signs a contribution.
// No field is a claim that all host/VM copies have been physically erased.
type guidedEnvironment struct {
	OS                            string `json:"os"`
	Architecture                  string `json:"architecture"`
	EntropySource                 string `json:"entropy_source"`
	ContributorSwapDisabled       bool   `json:"contributor_swap_disabled"`
	ContributorCrashDumpsDisabled bool   `json:"contributor_crash_dumps_disabled"`
	ContributorTelemetryDisabled  bool   `json:"contributor_telemetry_disabled"`
	EphemeralEnvironment          bool   `json:"ephemeral_environment"`
	EphemeralCleanupRequired      bool   `json:"ephemeral_cleanup_required"`
	HostRemnantsNotExcluded       bool   `json:"host_remnants_not_excluded"`
}

func (p *rolePreparer) environment() (string, error) {
	driver := dockerDriver{image: p.d.Values["image"], platform: p.d.Values["platform"], client: osDockerCommandClient{binary: "docker"}}
	preflight := p.environmentPreflight
	if preflight == nil {
		preflight = driver.preflight
	}
	if err := preflight(); err != nil {
		return "", err
	}
	fmt.Fprintln(p.ui.output, "Relay checked the local Docker endpoint, image platform and applicable swap requirements. During contribution it enforces an offline disposable container, disabled core dumps/logging, and verified cleanup. Those execution checks run again during your turn.")
	fmt.Fprintln(p.ui.output, "Use the agreed machine and backup precautions. Do not deliberately retain contribution randomness, memory dumps or snapshots. Docker cleanup cannot exclude host/VM remnants; this is not proof of physical erasure.")
	if err := p.ui.confirm("Confirm these are the precautions you will follow and that you understand the host/VM limitation", "PRECAUTIONS REVIEWED"); err != nil {
		return "", err
	}
	env := guidedEnvironment{"linux", runtime.GOARCH, "operating-system-csprng", true, true, true, true, true, true}
	canonical, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	path := filepath.Join(p.d.Work, "environment.json")
	if saved := p.d.Values["environment"]; saved != "" {
		if filepath.Dir(saved) != p.d.Work {
			return "", errors.New("saved environment must remain in this role's work folder")
		}
		path = saved
	}
	if _, err := os.Lstat(path); err == nil {
		var existing guidedEnvironment
		if err := setupReadJSON(path, &existing); err != nil {
			return "", err
		}
		if existing != env {
			return "", errors.New("existing environment differs; preserve it and review before changing the participant profile")
		}
		raw, err := readPreparationInput(path)
		if err != nil {
			return "", err
		}
		if !bytes.Equal(raw, canonical) {
			// Older guides emitted indented JSON. Preserve that unsigned plan and
			// allocate canonical bytes for the fresh profile rather than overwriting.
			f := roleFlow{state: roleFlowState{Profile: guidedProfile{Work: p.d.Work}}}
			fresh, err := f.freshOutputDefault("/work/environment.json")
			if err != nil {
				return "", err
			}
			path = flowHostPath(f.state.Profile, fresh)
			if err := writePublicTextOnce(path, string(canonical)); err != nil {
				return "", err
			}
			fmt.Fprintf(p.ui.output, "Preserved the earlier noncanonical plan; the fresh profile will use %s. Existing profiles were not changed.\n", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	} else if err := writePublicTextOnce(path, string(canonical)); err != nil {
		return "", err
	}
	p.d.Values["environment"] = path
	return path, p.save()
}
