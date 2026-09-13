// Package storagesetup embeds the reviewed administrator helper in the launcher.
package storagesetup

import "embed"

// AWS contains only the AWS helper and its non-secret settings exporter.
//
//go:embed setup-aws.sh coordinator-settings.sh
var AWS embed.FS
