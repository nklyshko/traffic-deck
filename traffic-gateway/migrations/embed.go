// Package migrations embeds the SQL migration files so the gateway binary can
// apply them without needing the source tree at runtime.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
