// Package release embeds reviewed defaults in the versioned launcher.
package release

import _ "embed"

//go:embed ceremony-policy.json
var ceremonyPolicy string

// CeremonyPolicy returns a fresh copy of the template shipped with this build.
func CeremonyPolicy() []byte { return []byte(ceremonyPolicy) }
