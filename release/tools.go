package release

import _ "embed"

//go:embed role-images.json
var roleImageInputs string

// RoleImageInputs binds downloadable proof tools to the launcher source release.
func RoleImageInputs() []byte { return []byte(roleImageInputs) }
