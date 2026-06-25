package store

import _ "embed"

//go:embed schema/catalog.sql
var catalogSchema string

//go:embed schema/session.sql
var sessionSchema string
