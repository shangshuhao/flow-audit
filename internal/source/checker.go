package source

import "context"

// Checker can perform a read-only runtime permission and capability check.
type Checker interface {
	Check(context.Context) error
}
