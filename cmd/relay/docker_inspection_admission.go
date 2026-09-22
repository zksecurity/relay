package main

import "path/filepath"

// Read-only inspections also consume capacity. Their recovery records live in
// the daemon's private admission directory, never in a public transcript or a
// temporary authenticated snapshot. The exact read-only invocation identifies
// an inspection; ordinary signing/contribution operation identity is separate.
func (d *dockerDriver) admittedInspectionOutput(runArgs []string) ([]byte, []byte, error) {
	if err := d.authenticateDaemon(); err != nil {
		return nil, nil, err
	}
	limits, err := resolvedDockerRuntimeLimits(d.runtimeLimits)
	if err != nil {
		return nil, nil, err
	}
	work := filepath.Join(filepath.Dir(dockerResourcePolicyPath(d.daemon.ID)), "inspections")
	o := dockerRoleOptions{role: "inspector", image: d.image, platform: d.platform, work: work, runtimeLimits: &limits}
	id, err := prepareAdmittedDockerRole(d.client, d.daemon, o, runArgs, runArgs)
	if err != nil {
		return nil, nil, err
	}
	return d.client.Output("start", "--attach", id)
}
