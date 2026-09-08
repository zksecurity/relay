package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/zksecurity/relay/internal/access"
	"github.com/zksecurity/relay/internal/transcript"
)

type flowHeadCheckpoint struct {
	Count          int
	LastID, Digest string
}
type flowHead struct {
	Chain  transcript.Chain
	Digest string
}

// Selection uses authenticated projections, never filename ordering. A local
// maximum is not a claim that no newer head exists on another machine.
func selectFlowHead(heads []flowHead, previous flowHeadCheckpoint) (flowHead, error) {
	if previous.Count < 0 || (previous.Count > 0 && (previous.LastID == "" || previous.Digest == "")) {
		return flowHead{}, errors.New("invalid saved head checkpoint")
	}
	if len(heads) == 0 {
		return flowHead{}, errors.New("no signed chains found; import or synchronize the phase transcript first")
	}
	sort.Slice(heads, func(i, j int) bool { return len(heads[i].Chain.Records) < len(heads[j].Chain.Records) })
	best := heads[len(heads)-1]
	for _, head := range heads {
		if head.Chain.CeremonyID != best.Chain.CeremonyID || head.Chain.Phase != best.Chain.Phase || (len(head.Chain.Records) > 0 && !reflect.DeepEqual(head.Chain.Records, best.Chain.Records[:len(head.Chain.Records)])) {
			return flowHead{}, errors.New("conflicting authenticated chains; stop and resolve the fork with the coordinator")
		}
		if len(head.Chain.Records) == len(best.Chain.Records) && head.Digest != best.Digest {
			return flowHead{}, errors.New("different signed heads at the same position; do not choose automatically")
		}
	}
	if previous.Digest != "" {
		count := len(best.Chain.Records)
		if count < previous.Count || (count == previous.Count && best.Digest != previous.Digest) || (previous.Count > 0 && (previous.Count > count || best.Chain.Records[previous.Count-1].RecordID != previous.LastID)) {
			return flowHead{}, errors.New("local transcript rolled back or diverged from a previously authenticated head")
		}
	}
	return best, nil
}

func commandValue(command []string, flag string) string {
	for n, arg := range command {
		if arg == "--"+flag && n+1 < len(command) {
			return command[n+1]
		}
	}
	return ""
}

func (f *roleFlow) discoverHead(phase string, command []string) (flowHead, error) {
	p := f.state.Profile
	root, ceremony, signature, key := "/work/ceremony/public", commandValue(command, "ceremony"), commandValue(command, "ceremony-signature"), commandValue(command, "coordinator-public-key-file")
	for _, flag := range []string{"transcript-dir", "transcript-root"} {
		if v := commandValue(command, flag); v != "" {
			root = v
		}
	}
	if ceremony == "" {
		// Transport recipes carry their authenticated local configuration rather
		// than direct trust flags. Never derive a key from downloaded metadata.
		configPath := commandValue(command, "config")
		if configPath != "" {
			var c access.RoleConfig
			if err := setupReadJSON(flowHostPath(p, configPath), &c); err != nil {
				return flowHead{}, err
			}
			if err := c.Validate(); err != nil {
				return flowHead{}, err
			}
			ceremony, signature, key, root = c.Ceremony, c.CeremonySignature, c.CoordinatorKey, c.Root
		} else {
			ceremony, signature = "/work/ceremony/public/ceremony.json", "/work/ceremony/public/ceremony.sig"
			key = f.state.Values["shared/coordinator-public-key-file"]
			if key == "" {
				key = "/trust/coordinator-public-key.hex"
			}
		}
	}
	bindings := []string{"--ceremony", ceremony, "--ceremony-signature", signature, "--coordinator-public-key-file", key}
	if err := f.bindPublicInputs(bindings); err != nil {
		return flowHead{}, err
	}
	hostRoot, err := f.publicHostPath(root)
	if err != nil {
		return flowHead{}, err
	}
	hostDefinition, err := f.publicHostPath(ceremony)
	if err != nil {
		return flowHead{}, err
	}
	hostSignature, err := f.publicHostPath(signature)
	if err != nil {
		return flowHead{}, err
	}
	hostKey, err := f.publicHostPath(key)
	if err != nil {
		return flowHead{}, err
	}
	client := osDockerCommandClient{binary: "docker"}
	_, endpoint, err := resolveDockerEndpoint(client)
	if err != nil {
		return flowHead{}, err
	}
	if err := validateLocalDockerEndpoint(endpoint); err != nil {
		return flowHead{}, err
	}
	if err := prepareGuidedImage(p.Image, p.Platform, "docker", false); err != nil {
		return flowHead{}, err
	}
	d := dockerDriver{image: p.Image, platform: p.Platform, ceremonyBinary: "/usr/local/bin/mpc-ceremony", root: hostRoot, definition: hostDefinition, definitionSig: hostSignature, coordinatorKey: hostKey, client: client.BindHost(endpoint)}
	i := d.inspector()
	definition, err := i.Definition()
	if err != nil {
		return flowHead{}, err
	}
	entries, err := os.ReadDir(filepath.Join(hostRoot, phase))
	if err != nil {
		return flowHead{}, fmt.Errorf("import the %s transcript first: %w", phase, err)
	}
	if len(entries) > 1024 {
		return flowHead{}, errors.New("too many phase directory entries to discover safely")
	}
	var heads []flowHead
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "chain-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if !entry.Type().IsRegular() {
			return flowHead{}, errors.New("chain discovery refuses directories and symlinks")
		}
		path := filepath.Join(hostRoot, phase, name)
		sig := strings.TrimSuffix(path, ".json") + ".sig"
		before, err := setupFileHash(path)
		if err != nil {
			return flowHead{}, err
		}
		chain, err := i.Chain(path, sig)
		if err != nil {
			return flowHead{}, fmt.Errorf("authenticate %s: %w", name, err)
		}
		after, err := setupFileHash(path)
		if err != nil || after != before {
			return flowHead{}, errors.New("chain changed during authentication")
		}
		if chain.Phase != phase || chain.CeremonyID != definition.CeremonyID {
			return flowHead{}, errors.New("chain belongs to another ceremony or phase")
		}
		heads = append(heads, flowHead{chain, after})
	}
	var previous flowHeadCheckpoint
	if raw := f.state.Values["head/"+phase]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &previous); err != nil {
			return flowHead{}, err
		}
	}
	best, err := selectFlowHead(heads, previous)
	if err != nil {
		return flowHead{}, err
	}
	checkpoint := flowHeadCheckpoint{Count: len(best.Chain.Records), Digest: best.Digest}
	if checkpoint.Count > 0 {
		checkpoint.LastID = best.Chain.Records[checkpoint.Count-1].RecordID
	}
	raw, _ := json.Marshal(checkpoint)
	f.state.Values["head/"+phase] = string(raw)
	if err := f.save(); err != nil {
		return flowHead{}, err
	}
	fmt.Fprintf(f.ui.output, "Authenticated local %s head: %d contributions. This is the most advanced consistent local copy, not proof that no newer published head exists.\n", phase, len(best.Chain.Records))
	return best, nil
}

func flowHeadPhase(field flowField) string {
	if field.Flag != "chain" && field.Flag != "phase1-chain" && field.Flag != "phase2-chain" {
		return ""
	}
	for _, phase := range []string{"phase1", "phase2"} {
		if strings.Contains(field.Default, "/"+phase+"/") {
			return phase
		}
	}
	return ""
}
