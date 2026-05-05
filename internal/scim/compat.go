package scim

import "strings"

// CompatMode represents SCIM compatibility mode.
type CompatMode int

const (
	CompatNone CompatMode = iota
	CompatMS
)

func ParseCompatMode(s string) CompatMode {
	if strings.EqualFold(s, "ms") {
		return CompatMS
	}
	return CompatNone
}
